import { createHash } from "node:crypto";
import type { DispatchPayload, NewEvent, RunKind, RunOutcome } from "../../contracts/events.js";
import { journalAnswers, noAnswers, type Answers } from "../../core/answers.js";
import { commitTurn, type Harness, type Outcome, type TurnConfig } from "../../core/loop.js";
import { drain, streamTurn } from "../../core/stream.js";
import { SpecError, type RoleSpec, type RunSpec } from "../../core/spec.js";
import { topologyFor, type Assignment, type Round } from "../../core/topology.js";

// What every arch's lead emits. Everything past action is arch-specific and read
// only when the arch declared it, so one loop drives a swarm and a single lead.
export interface Decision {
  action: string;
  rationale: string;
  worker_agent_id?: string | null;
  query_intent?: string;
}

export interface DecisionPayload {
  action: string;
  rationale: string;
  worker: string | null;
}

export interface FindingPayload {
  agent_id: string;
  answer: unknown;
}

export type LeadKinds = { decision: DecisionPayload; finding: FindingPayload };
type Event = NewEvent<LeadKinds>;

export interface LeadOptions {
  run_id: string;
  run_kind: RunKind;
  spec: RunSpec;
  actions: readonly string[];
  halts: readonly string[];
  started_by?: string;
  // Where an answer to a parked call comes from. Defaults to nobody, so a run
  // with no source parks and stays parked rather than proceeding unapproved.
  answers?: Answers;
  // Aborted when this worker loses its lease. The provider request carries it, so
  // a worker that has been declared dead stops paying for a call nobody records.
  signal?: AbortSignal;
}

export interface LeadReport {
  status: RunOutcome | "waiting_approval";
  reason: string;
  iterations: number;
  dispatched: number;
  pending: Outcome<unknown>["pending"];
}

// Deny-by-default per role, straight off the arch: what the registry grants is
// what the arch declared, so a role never sees a catalogue.
export function grantsOf(spec: RunSpec): Record<string, readonly string[]> {
  const workers = Object.entries(spec.roles.workers).map(([id, role]) => [id, role.tools]);
  return {
    ...(spec.roles.lead === undefined ? {} : { lead: spec.roles.lead.tools }),
    ...(spec.roles.critic === undefined ? {} : { critic: spec.roles.critic.tools }),
    ...Object.fromEntries(workers),
  };
}

// The deterministic half, driven entirely by the arch: one decision per iteration,
// a worker turn when the decision names one, and an ending the model cannot force.
export async function runLead(harness: Harness<LeadKinds>, options: LeadOptions): Promise<LeadReport> {
  const { run_id, spec } = options;
  const lead = spec.roles.lead;
  // Refused at the door rather than per iteration: a lead-less arch belongs to a
  // workflow that sequences itself, and running it here would decide nothing.
  if (lead === undefined) throw new SpecError(`arch ${spec.arch} declares no lead, so it cannot run a lead loop`);
  if ((await harness.state.latestSeq(run_id)) === null) await open(harness, options);

  const topology = topologyFor(spec.dispatch.topology);
  const rounds: Round[] = [];
  for (;;) {
    // Per iteration, not once per resume. The loop reads the ledger to decide
    // whether it is still parked, so an answer journaled after that check used to
    // wait for a whole resume; now it waits for one iteration boundary.
    await journalAnswers(harness.state, run_id, options.run_kind, options.answers ?? noAnswers);

    const outcome = await drain(streamTurn<Decision, LeadKinds>(turnFor(options, "lead", lead, brief(spec)), harness));
    if (outcome.status === "waiting_approval") {
      await commitTurn(harness.state, run_id, outcome, []);
      return { ...(await report(harness, options)), status: "waiting_approval", reason: outcome.reason, pending: outcome.pending };
    }
    if (outcome.status === "failed" || outcome.value === null) {
      await commitTurn(harness.state, run_id, outcome, []);
      return end(harness, options, outcome.refusal === null ? "failed" : "budget_exhausted", outcome.reason);
    }

    const decision = outcome.value;
    const selection = { worker: named(spec, decision), task: decision.query_intent ?? decision.rationale };
    const assignments = topology.assign(selection, spec);
    await commitTurn(harness.state, run_id, outcome, [
      event(options, "decision", { action: decision.action, rationale: decision.rationale, worker: selection.worker }),
    ]);

    for (const assignment of assignments) await dispatch(harness, options, assignment);
    rounds.push({ assigned: assignments.length });

    // Termination is the arch's, not the model's: an action outside the halting
    // set keeps the run going however confident the rationale sounds.
    if (options.halts.includes(decision.action)) return end(harness, options, "completed", decision.rationale);
    // The topology's own ending, which is a different claim: a swarm that has
    // gone quiet is finished whether or not anyone said so.
    if (topology.settled(rounds)) return end(harness, options, "completed", `the ${topology.id} went quiet`);
  }
}

// A worker the arch declares, or nothing. A name the roster does not hold is a
// decision the loop refuses to act on rather than one it invents a worker for.
function named(spec: RunSpec, decision: Decision): string | null {
  const id = decision.worker_agent_id;
  return typeof id === "string" && id in spec.roles.workers ? id : null;
}

async function dispatch(harness: Harness<LeadKinds>, options: LeadOptions, assignment: Assignment): Promise<void> {
  const { role: worker, task: intent } = assignment;
  const role = options.spec.roles.workers[worker] as RoleSpec;
  const outcome = await drain(streamTurn<unknown, LeadKinds>(turnFor(options, worker, role, intent), harness));

  const complete = outcome.status === "completed";
  const payload: DispatchPayload = {
    dispatch_id: `dsp-${digest(`${options.run_id}\n${worker}\n${intent}`)}`,
    agent_id: worker,
    status: complete ? "complete" : "failed",
    question_id: null,
    failure_reason: complete ? null : outcome.reason,
  };
  const own: Event[] = [event(options, "dispatch", payload)];
  if (outcome.value !== null) own.push(event(options, "finding", { agent_id: worker, answer: outcome.value }));
  await commitTurn(harness.state, options.run_id, outcome, own);
}

function turnFor(options: LeadOptions, role: string, spec: RoleSpec, task: string): TurnConfig {
  const { runtime } = options.spec;
  return {
    run_id: options.run_id,
    run_kind: options.run_kind,
    role,
    system: spec.prompt,
    task,
    schema: spec.output_schema,
    max_turns: runtime.max_turns,
    approvals: new Set(options.spec.approvals),
    verbs: options.actions,
    result_cap: runtime.result_cap,
    recall_limit: runtime.recall_limit,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  };
}

// The playbook's half, rendered once: what this run is about and what an analyst
// should know. The fold that replaces it with a digest is a later slice.
function brief(spec: RunSpec): string {
  const objectives = spec.objectives.map((line) => `- ${line}`).join("\n");
  const parts = [`Run: ${spec.name}`, objectives && `Objectives:\n${objectives}`, spec.narrative];
  return parts.filter((part) => part).join("\n\n");
}

function event(options: LeadOptions, kind: Event["kind"], payload: Event["payload"]): Event {
  return { run_id: options.run_id, run_kind: options.run_kind, kind, payload };
}

async function open(harness: Harness<LeadKinds>, options: LeadOptions): Promise<void> {
  await harness.state.append(options.run_id, 0, [
    event(options, "run", {
      run_kind: options.run_kind,
      spec: options.spec,
      budgets: harness.budget.limits,
      seed: options.run_id,
      tenant_id: null,
      started_by: options.started_by ?? "worker",
    }),
  ]);
}

async function end(harness: Harness<LeadKinds>, options: LeadOptions, outcome: RunOutcome, reason: string): Promise<LeadReport> {
  const from = ((await harness.state.latestSeq(options.run_id)) ?? -1) + 1;
  await harness.state.append(options.run_id, from, [event(options, "terminal", { outcome, reason })]);
  return { ...(await report(harness, options)), status: outcome, reason, pending: null };
}

// Folded rather than counted in a local, so a resumed run reports what the
// ledger holds and not what this process happened to do.
async function report(harness: Harness<LeadKinds>, options: LeadOptions): Promise<Omit<LeadReport, "status" | "reason" | "pending">> {
  const events = await harness.state.read(options.run_id);
  // Decisions, not model calls: the harness counts a call per turn and per
  // emission attempt, which is spend, while an arch's max_calls means these.
  return {
    iterations: events.filter((one) => one.kind === "decision").length,
    dispatched: events.filter((one) => one.kind === "dispatch").length,
  };
}

function digest(material: string): string {
  return createHash("sha256").update(material).digest("hex").slice(0, 12);
}
