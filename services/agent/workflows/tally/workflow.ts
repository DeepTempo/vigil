import type { NewEvent, RunOutcome } from "../../contracts/events.js";
import { commitTurn, type Attempt, type Harness, type Outcome, type TurnConfig } from "../../core/loop.js";
import { drain, streamTurn } from "../../core/stream.js";
import type { State } from "../../core/seams.js";
import { SYSTEM, TALLY_SCHEMA, TALLY_VERBS, type TallyKinds, type TallyPayload } from "./vocabulary.js";

export interface TallyOptions {
  run_id: string;
  target: number;
  max_turns: number;
  approvals?: ReadonlySet<string>;
  started_by?: string;
}

export interface TallyReport {
  status: RunOutcome | "waiting_approval";
  reason: string;
  count: number;
  iterations: number;
  pending: Outcome<unknown>["pending"];
}

type Emission = { verb: TallyPayload["verb"]; note: string };
type Event = NewEvent<TallyKinds>;

// The deterministic half: the vocabulary, what each verb does, and when the run may
// end. Nothing here reaches a model or a tool except through the harness.
export async function runTally(harness: Harness<TallyKinds>, options: TallyOptions): Promise<TallyReport> {
  const { run_id } = options;
  if ((await harness.state.latestSeq(run_id)) === null) await open(harness, options);

  for (;;) {
    const count = await countOf(harness.state, run_id);
    // The harness counts every model call against the pool, so a run whose model
    // never says HALT is ended by the budget refusing the next one.
    const outcome = await drain(streamTurn<Emission, TallyKinds>(config(options, count), harness));

    if (outcome.status === "waiting_approval") {
      await commitTurn(harness.state, run_id, []);
      return { ...(await report(harness, run_id)), status: "waiting_approval", reason: outcome.reason, pending: outcome.pending };
    }

    if (outcome.status === "failed" || outcome.value === null) {
      await commitTurn(harness.state, run_id, []);
      const status = outcome.refusal === null ? "failed" : "budget_exhausted";
      return end(harness, options, status, outcome.reason);
    }

    const reached = countFrom(outcome.calls, count);
    const applied: TallyPayload = { verb: outcome.value.verb, count: reached, note: outcome.value.note };
    await commitTurn(harness.state, run_id, [{ run_id, run_kind: "tally", kind: "tally", payload: applied }]);

    // Termination is the workflow's, and it is a predicate the model does not
    // control: HALT is honoured, but reaching the target ends the run regardless.
    if (reached >= options.target) return end(harness, options, "completed", `the count reached ${reached}`);
    if (applied.verb === "HALT") return end(harness, options, "completed", applied.note);
  }
}

async function open(harness: Harness<TallyKinds>, options: TallyOptions): Promise<void> {
  const event: Event = {
    run_id: options.run_id,
    run_kind: "tally",
    kind: "run",
    payload: {
      run_kind: "tally",
      spec: { target: options.target, max_turns: options.max_turns },
      budgets: harness.budget.limits,
      seed: options.run_id,
      tenant_id: null,
      started_by: options.started_by ?? "tally",
    },
  };
  await harness.state.append(options.run_id, [event]);
}

async function end(
  harness: Harness<TallyKinds>,
  options: TallyOptions,
  outcome: RunOutcome,
  reason: string,
): Promise<TallyReport> {
  const event: Event = { run_id: options.run_id, run_kind: "tally", kind: "terminal", payload: { outcome, reason } };
  await harness.state.append(options.run_id, [event]);
  return { ...(await report(harness, options.run_id)), status: outcome, reason, pending: null };
}

async function report(harness: Harness<TallyKinds>, runId: string): Promise<Omit<TallyReport, "status" | "reason" | "pending">> {
  return { count: await countOf(harness.state, runId), iterations: harness.budget.spent.calls };
}

function config(options: TallyOptions, count: number): TurnConfig {
  return {
    run_id: options.run_id,
    run_kind: "tally",
    role: "counter",
    system: SYSTEM,
    task: `The count is ${count}. The target is ${options.target}.`,
    schema: TALLY_SCHEMA,
    max_turns: options.max_turns,
    approvals: options.approvals ?? new Set(),
    verbs: TALLY_VERBS,
    result_cap: 2_000,
    recall_limit: 3,
  };
}

// The projection, folded rather than stored: the last tally event carries where
// the count got to, so two folds of one ledger agree by construction.
async function countOf(state: State<TallyKinds>, runId: string): Promise<number> {
  const events = await state.read(runId);
  const last = events.filter((event) => event.kind === "tally").at(-1);
  return last === undefined ? 0 : (last.payload as TallyPayload).count;
}

// The rows, never the rendering: what the model read went through wrap, and the
// workflow reads the structured result the same call produced.
function countFrom(calls: readonly Attempt[], fallback: number): number {
  for (const call of [...calls].reverse()) {
    if (!call.result.ok) continue;
    const row = call.result.rows[0] as { count?: unknown } | undefined;
    if (typeof row?.count === "number") return row.count;
  }
  return fallback;
}
