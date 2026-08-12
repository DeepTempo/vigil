import { InProcessState } from "../../core/state.js";
import type { BudgetLimits } from "../../contracts/budget.js";
import { DEFAULT_BUDGETS, DEFAULT_DISPATCH, DEFAULT_RUNTIME, type RunSpec } from "../../core/spec.js";
import { DEFAULT_CHECKPOINTS, type Checkpoints } from "../../workflows/hunt/checkpoints.js";
import {
  DEFAULT_ENRICHMENT,
  DEFAULT_HYPOTHESIS_LOOP,
  DEFAULT_TERMINATION,
  DEFAULT_VERDICTS,
  type HuntSpec,
  type Termination,
  type Verdicts,
} from "../../workflows/hunt/config.js";
import { HuntController, startHunt } from "../../workflows/hunt/controller.js";
import { Journal, type HuntEvent, type HuntKinds } from "../../workflows/hunt/journal.js";
import { newId } from "../../workflows/hunt/ids.js";
import type { Enricher, WorkerDispatcher } from "../../workflows/hunt/ports.js";
import type { HuntReport } from "../../workflows/hunt/report.js";
import {
  ScriptedDecisionProvider,
  ScriptedDisconfirmationCritic,
  type ScriptedDecision,
} from "../../workflows/hunt/scripted.js";
import { NULL_CHECK_PROVENANCE, unclassified } from "../../workflows/hunt/strength.js";
import type { Decision, Entity, EvidenceRecord, LinkRelation } from "../../workflows/hunt/types.js";

export const INVESTIGATE: Decision = { action: "INVESTIGATE", rationale: "look", query_intent: "baseline" };
export const CONCLUDE: Decision = { action: "CONCLUDE", rationale: "nothing further to run" };
export const SEED_IP: Entity = { type: "ip", value: "45.77.53.176" };

const LEAD = { prompt: "lead", description: "the hunt lead", output_schema: {}, tools: [] };

export interface SpecOverrides {
  hypotheses?: string[];
  budgets?: BudgetLimits;
  termination?: Partial<Termination>;
  checkpoints?: Partial<Checkpoints>;
  scope?: Record<string, unknown>;
  dispatch?: RunSpec["dispatch"];
  hypothesisLoop?: boolean;
}

// Built as an object rather than parsed from three files: the loader has its own
// tests, and a controller test that had to write YAML would be testing both.
export function huntSpecFor(overrides: SpecOverrides = {}): HuntSpec {
  const hypotheses = overrides.hypotheses ?? ["a credential is used from new infrastructure"];
  return {
    sections: {},
    model: "scripted",
    budgets: overrides.budgets ?? DEFAULT_BUDGETS,
    runtime: DEFAULT_RUNTIME,
    tools: [],
    approvals: [],
    thresholds: {},
    arch: "threathunt",
    hypothesis_loop: overrides.hypothesisLoop ?? DEFAULT_HYPOTHESIS_LOOP,
    name: "test hunt",
    description: "",
    use_case: "",
    trigger_examples: [],
    phases: [],
    prompt: "",
    objectives: [],
    scope: overrides.scope ?? {},
    narrative: "",
    roles: { lead: LEAD, workers: {} },
    dispatch: overrides.dispatch ?? DEFAULT_DISPATCH,
    digest: {},
    hypotheses,
    attack_techniques: [],
    data_domains: [],
    enrichment: DEFAULT_ENRICHMENT,
    checkpoints: { ...DEFAULT_CHECKPOINTS, ...overrides.checkpoints },
    termination: { ...DEFAULT_TERMINATION, ...overrides.termination },
  };
}

export interface Started {
  ledger: Journal;
  state: InProcessState<HuntKinds>;
  runId: string;
  hypothesisIds: string[];
}

export async function newLedger(overrides: SpecOverrides = {}): Promise<Started> {
  const state = new InProcessState<HuntKinds>();
  const runId = newId("run");
  const ledger = await startHunt(state, runId, huntSpecFor(overrides));
  return { ledger, state, runId, hypothesisIds: [...ledger.projection.hypotheses.keys()] };
}

// What an operator answering a checkpoint hours later does: nothing of the
// writing process carries over, the ledger is the whole state.
export async function reopen(started: Started, from?: Journal): Promise<Journal> {
  await (from ?? started.ledger).flush();
  return Journal.open(started.state, started.runId);
}

export interface ControllerOptions {
  critic?: ScriptedDisconfirmationCritic;
  dispatcher?: WorkerDispatcher;
  enricher?: Enricher;
  costPerDecision?: number;
  verdicts?: Verdicts;
  provider?: ScriptedDecisionProvider;
  dispatch?: RunSpec["dispatch"];
  maxWorkers?: number;
}

export function controllerFor(
  ledger: Journal,
  decisions: ScriptedDecision[],
  options: ControllerOptions = {},
): HuntController {
  const dispatch =
    options.dispatch ??
    (options.dispatcher === undefined
      ? undefined
      : { ...DEFAULT_DISPATCH, mode: "parallel" as const, max_workers: options.maxWorkers ?? 3 });
  return new HuntController(
    ledger,
    options.provider ?? new ScriptedDecisionProvider(decisions, options.costPerDecision ?? 0),
    options.dispatcher,
    dispatch,
    undefined,
    options.enricher,
    options.critic,
    options.verdicts ?? DEFAULT_VERDICTS,
  );
}

export interface EvidenceOptions {
  source?: string;
  relation?: LinkRelation;
  attackerInfluenceable?: boolean;
  entities?: Entity[];
}

export function evidenceOn(ledger: Journal, hypothesisId: string, options: EvidenceOptions = {}): string {
  const source = options.source ?? "duckdb";
  const evidenceId = newId("ev");
  ledger.append({
    kind: "evidence",
    payload: {
      evidence_id: evidenceId,
      dispatch_id: null,
      iteration: 1,
      source_system: source,
      summary: `${source} saw the identity authenticate from ${SEED_IP.value}`,
      payload: { rows: 3, src_ip: SEED_IP.value },
      salience: "notable",
      why_notable: "first use of this ASN by the identity",
      provenance: "worker",
      attacker_influenceable: options.attackerInfluenceable ?? false,
      instruction_like: false,
      entities: options.entities ?? [],
      captured_at: new Date().toISOString(),
    },
  });
  ledger.append({
    kind: "link",
    payload: { evidence_id: evidenceId, hypothesis_id: hypothesisId, relation: options.relation ?? "supports" },
  });
  return evidenceId;
}

// Evidence with no link at all, so a test can wire the relations it needs
// across several hypotheses rather than the single one evidenceOn assumes.
export function bareEvidence(ledger: Journal, source = "duckdb", iteration = 1): string {
  const evidenceId = newId("ev");
  ledger.append({
    kind: "evidence",
    payload: {
      evidence_id: evidenceId,
      dispatch_id: null,
      iteration,
      source_system: source,
      summary: `${source} observed something`,
      payload: { rows: 3 },
      salience: "notable",
      why_notable: "",
      provenance: "worker",
      attacker_influenceable: false,
      instruction_like: false,
      entities: [],
      captured_at: new Date().toISOString(),
    },
  });
  return evidenceId;
}

export function relate(ledger: Journal, evidenceId: string, hypothesisId: string, relation: LinkRelation): void {
  ledger.append({ kind: "link", payload: { evidence_id: evidenceId, hypothesis_id: hypothesisId, relation } });
}

// Enough support to clear every verdict predicate, so what a test is measuring is
// the checkpoint or the termination rather than the strength computation.
export function provable(ledger: Journal, hypothesisId: string): string[] {
  return [
    evidenceOn(ledger, hypothesisId, { source: "cloudtrail", entities: [SEED_IP] }),
    evidenceOn(ledger, hypothesisId, { source: "duckdb", entities: [SEED_IP] }),
  ];
}

// A query the hunt wanted and could not run, recorded the way a failed dispatch
// records one — each distinct blind spot needs its own intent.
let unanswered = 0;
export function gapOn(ledger: Journal, hypothesisId: string | null, intent = `question ${(unanswered += 1)}`): void {
  const dispatchId = newId("dsp");
  ledger.append({
    kind: "dispatch",
    payload: {
      dispatch_id: dispatchId,
      iteration: 1,
      agent_id: "threat_hunter",
      status: "failed",
      query_intent: intent,
      target_hypothesis_id: hypothesisId,
      question_id: null,
      failure_reason: "timeout",
      cost_usd: 0,
      calls: [],
    },
  });
  ledger.append({
    kind: "evidence",
    payload: {
      evidence_id: newId("ev"),
      dispatch_id: dispatchId,
      iteration: 1,
      source_system: "dispatcher",
      summary: "worker failed: timeout",
      payload: {},
      salience: "routine",
      why_notable: "a query the hunt wanted could not be run",
      provenance: "tool_failure",
      attacker_influenceable: false,
      instruction_like: false,
      entities: [],
      captured_at: new Date().toISOString(),
    },
  });
}

export interface QuestionFields {
  entity_key?: string | null;
  spawned_iteration?: number;
  status?: "open" | "closed";
  hypothesis_id?: string | null;
  spawning_evidence_id?: string | null;
}

export function question(ledger: Journal, text: string, fields: QuestionFields = {}): string {
  const questionId = newId("q", 4);
  ledger.append({
    kind: "question",
    payload: {
      question_id: questionId,
      question: text,
      status: fields.status ?? "open",
      entity_key: fields.entity_key ?? null,
      spawning_evidence_id: fields.spawning_evidence_id ?? null,
      spawning_dispatch_id: null,
      spawned_iteration: fields.spawned_iteration ?? 1,
      hypothesis_id: fields.hypothesis_id ?? null,
      closed_reason: null,
    },
  });
  return questionId;
}

export function validateOn(hypothesisId: string, citations: string[], extra: Partial<Decision> = {}): Decision {
  return {
    action: "VALIDATE",
    rationale: "the support looks solid enough to put up for a verdict",
    target_hypothesis_id: hypothesisId,
    evidence_citations: citations,
    ...extra,
  };
}

// Rules on whatever the loop still needs ruled, as "neither": evidence gathered
// for one hypothesis usually says nothing about the others, and silence is refused.
export function ruled<T extends Decision>(ledger: Journal, decision: T): T {
  const pending = unclassified(ledger.projection);
  if (pending.length === 0) return decision;
  return { ...decision, evidence_relations: pending.map((pair) => ({ ...pair, relation: "neither" as const })) };
}

// Terminal by any route the hunt actually has; the predicate cares that nothing
// is active, not how it got there.
export function resolve(ledger: Journal, hypothesisId: string, status = "parked"): void {
  ledger.patch("hypothesis", hypothesisId, { status, resolution_reason: `${status} for this test` });
}

// Drives one hypothesis to inconclusive through the real gap-lock path: enough
// support to clear every other predicate, and enough blindness that it cannot be.
export async function gapLock(ledger: Journal, hypothesisId: string): Promise<void> {
  const citations = [
    evidenceOn(ledger, hypothesisId, { source: "cloudtrail" }),
    evidenceOn(ledger, hypothesisId, { source: "duckdb" }),
  ];
  for (let gap = 0; gap < DEFAULT_VERDICTS.gap_lock_threshold; gap += 1) gapOn(ledger, hypothesisId);
  await controllerFor(ledger, [ruled(ledger, validateOn(hypothesisId, citations))], {
    critic: new ScriptedDisconfirmationCritic(true),
  }).advanceIteration();
}

export function nullChecks(ledger: Journal): EvidenceRecord[] {
  return [...ledger.projection.evidence.values()].filter((r) => r.provenance === NULL_CHECK_PROVENANCE);
}

export function events(ledger: Journal): readonly HuntEvent[] {
  return ledger.log;
}

export function finalized(ledger: Journal): HuntReport[] {
  return events(ledger)
    .filter((event) => event.kind === "finalize")
    .map((event) => event.payload as HuntReport);
}
