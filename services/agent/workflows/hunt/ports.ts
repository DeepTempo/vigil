import type {
  Digest,
  DecisionResult,
  Directive,
  DispatchRequest,
  DispatchResult,
  Entity,
  NullCheckInput,
  NullCheckResult,
  WorkerEvidence,
} from "./types.js";

// Where a directive waits before the run takes it. Any process enqueues, only the
// run drains, and nothing is deleted on read: what is journaled is the ledger's fact.
export interface DirectiveQueue {
  enqueue(runId: string, directive: Directive): Promise<void>;
  pending(runId: string, journaled: readonly string[]): Promise<Directive[]>;
}

// The Hunt Lead: one digest in, exactly one typed decision out. Implementations
// never touch the ledger — the controller applies, validates, and persists.
export interface DecisionProvider {
  decide(digest: Digest): Promise<DecisionResult>;
}

// The evidence source. Returns records rather than appending them, so a worker
// can never mutate hypothesis or budget state. Must be idempotent on dispatch_id.
export interface WorkerDispatcher {
  dispatch(request: DispatchRequest): Promise<DispatchResult>;
}

// Argues the strongest benign explanation against a hypothesis before it may be
// proven. Like a worker it returns a finding the controller appends as Hunt
export interface DisconfirmationCritic {
  argueNull(check: NullCheckInput): Promise<NullCheckResult>;
}

// Every chain that applies to one entity, run without a model. A function rather
// than an interface because depth, dedup and the per-round cap are ledger facts
export type Enricher = (entity: Entity) => Promise<WorkerEvidence[]>;
