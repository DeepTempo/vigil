// The recall contract (#729): what a read of episodic memory returns, and the
// signature of the tool that performs one.
//
// One shape, carried two ways. The run-start read journals it verbatim as the
// recall event payload; a mid-run recall_entity call carries the same object as
// the single row of a ToolResult. A parallel payload would be a second contract,
// and the second one drifts.
//
// A mismatch between the halves fails as "no history", indistinguishable from an
// entity nobody has looked at. The Python half is core/memory/recall_contract.py
// and tests/unit/_ratchets/test_recall_contract_agrees.py fails when they
// disagree. Nothing imports either half yet -- #731 writes the rows, #732 lands
// the tool, the harness lands the event -- which is why a static check is the
// only one available.

import type { ToolResult } from "./tool.js";

export const RECALL_TOOL = "recall_entity";

// What the arch asks for; a ToolSpec binds it to the tool id via `provides`.
export const RECALL_CAPABILITY = "entity_recall";

// Keyed by the role names threathunt.yaml declares, not by a class called
// "worker" that appears in no file. Empties are decisions: the lead never
// queries, and narrative search -- the lead's alone -- ships no tool here.
export const RECALL_GRANTS = {
  lead: [],
  critic: [],
  threat_hunter: [RECALL_CAPABILITY],
  network_analyst: [RECALL_CAPABILITY],
  threat_intel: [RECALL_CAPABILITY],
} as const;

// Who concluded, as opposed to what the source is.
export const TRUST_LEVELS = ["analyst", "agent"] as const;
export type Trust = (typeof TRUST_LEVELS)[number];

// #728 owns this vocabulary; it is followed here, not restated.
export const SOURCE_TIERS = ["telemetry", "feed", "not_evidence"] as const;
export type SourceTier = (typeof SOURCE_TIERS)[number];

// Three-valued, because a flat corroborated list cannot express direction.
export const STANCES = ["supports", "weakens", "neither"] as const;
export type Stance = (typeof STANCES)[number];

// Keyed by kind and id, never run_id: a run-keyed schema cannot represent the
// Case-authored Verdicts the writer split requires. Nothing writes `analyst` yet.
export const INVESTIGATION_KINDS = ["hunt", "case", "analyst"] as const;
export type InvestigationKind = (typeof INVESTIGATION_KINDS)[number];

// handed_off is terminal for the hunt and not an ending of the claim, so it ranks
// up like a Gap while still carrying evidence, a window and sources.
// false_positive arrives only from a Case closure.
export const VERDICT_OUTCOMES = ["proven", "disproven", "inconclusive", "handed_off", "false_positive"] as const;
export type VerdictOutcome = (typeof VERDICT_OUTCOMES)[number];

// A retrospective sweep over old archives asserts its window rather than
// observing it, and ranking discounts the weaker one.
export const WINDOW_SOURCES = ["observed", "asserted"] as const;
export type WindowSource = (typeof WINDOW_SOURCES)[number];

// Each value traces to a line of the spec, because a disposition invented here is
// one #731 writes against and nothing reviews. Not `never_dispatched`: a
// hypothesis that reached inconclusive with nothing gathered *was* dispatched.
// Not `no_data_source` either -- a tool that could not answer is a Visibility
// Gap, which CONTEXT.md keeps distinct from a Declared Gap.
export const GAP_DISPOSITIONS = ["deprioritised", "no_evidence_gathered", "budget_exhausted"] as const;
export type GapDisposition = (typeof GAP_DISPOSITIONS)[number];

// The rule is `defang` then case-fold, in workflows/hunt/entities.ts. The
// exception is the half that breaks silently: an ARN's resource part and an AWS
// key id are case-significant, so folding them makes two principals one key and
// the join still returns rows, just the wrong ones.
export const KEY_CASE_SENSITIVE_TYPES = ["arn", "aws_key"] as const;

// Both ends inclusive. Separate from a conclusion date, because a sweep that
// concluded today about last March is not newly relevant.
export interface ActivityWindow {
  readonly first_seen: string;
  readonly last_seen: string;
}

// On every row, not the envelope: one read returns rows from many
// investigations. concluded_at is when the investigation concluded, not when the
// row was written -- the Distil polls, so an investigation that ended Monday can
// be written Wednesday carrying Monday's date, inside the freshness predicate and
// absent from the read that ran on Tuesday.
export interface RecalledProvenance {
  readonly investigation_kind: InvestigationKind;
  readonly investigation_id: string;
  readonly concluded_at: string;
}

// One row per entity, investigation and source, so growth tracks hunts and not
// telemetry volume.
export interface RecalledSighting extends RecalledProvenance {
  readonly entity_key: string;
  readonly source_system: string;
  readonly hit_count: number;
  readonly attacker_influenceable: boolean;
  readonly window: ActivityWindow;
}

// source_system is memory's own column, not a foreign key into either producer: a
// hunt-derived Verdict fills it from the Ledger, a Case-derived one from the
// data_source of its Findings. A not_evidence tier here is a defect rather than a
// weak row, and is representable so that it is visible.
export interface RecalledVerdictSource {
  readonly source_system: string;
  readonly stance: Stance;
  readonly source_tier: SourceTier;
}

export interface RecalledVerdict extends RecalledProvenance {
  // Stable, because the prose gets re-worded.
  readonly hypothesis_id: string;
  readonly statement: string;
  readonly outcome: VerdictOutcome;
  // Reaches no ranking function: confident-sounding model text must not move a
  // priority (ADR 0015). Carried for a human reading the run back.
  readonly rationale: string;
  // The entities the hypothesis named, typically one to three -- not the 38 to 76
  // its evidence touched, which stay reachable through Sightings (ADR 0016).
  readonly subject_entities: readonly string[];
  readonly attacker_influenceable_only: boolean;
  readonly trust: Trust;
  readonly window: ActivityWindow;
  readonly window_source: WindowSource;
  readonly sources: readonly RecalledVerdictSource[];
}

// No window, which is why a Gap is not a Verdict with an empty outcome.
export interface RecalledGap extends RecalledProvenance {
  readonly hypothesis_id: string;
  readonly statement: string;
  readonly disposition: GapDisposition;
  readonly reason: string;
  readonly subject_entities: readonly string[];
}

// Per reason, because the two mean different things to a caller: per_key_cap
// means one entity had more history than its share, overall means the read was
// broad. A total is the sum and is not restated.
export interface DroppedRows {
  readonly per_key_cap: number;
  readonly overall_cap: number;
}

export interface RecallDropped {
  readonly sightings: DroppedRows;
  readonly verdicts: DroppedRows;
  readonly gaps: DroppedRows;
}

// The parameters that chose this set, copied in rather than referenced: a RunSpec
// records the arch by name and not by version. Selection only -- the order the
// rows were *presented* in is a fold, so ranking may change without invalidating
// a historical Ledger.
export interface RecallRanking {
  readonly order: string;
  // Rows per kind, per key. Applied as a LATERAL and before the overall cap.
  readonly per_key_cap: number;
  // Rows across all kinds and keys.
  readonly overall_cap: number;
}

// Named as a value too, so recallOf can check for them at runtime, which is where
// the drift arrives.
export const RECALL_RESULT_KEYS = [
  "keys",
  "as_of",
  "sightings",
  "verdicts",
  "gaps",
  "dropped",
  "ranking",
] as const;

// No field is optional and no list nullable: an empty list means
// known-to-be-none, so an entity with no history is empty lists and zeros rather
// than an error.
export interface RecallResult {
  // Normalised, and as queried rather than as asked for: only Python writes an
  // Entity Key, so the extractor's output travels as candidate data.
  readonly keys: readonly string[];
  // The freshness filter that ran, and not a substitute for journaling the rows.
  readonly as_of: string;
  readonly sightings: readonly RecalledSighting[];
  readonly verdicts: readonly RecalledVerdict[];
  readonly gaps: readonly RecalledGap[];
  readonly dropped: RecallDropped;
  readonly ranking: RecallRanking;
}

// The event payload is the result. An alias, because a copied interface would say
// only that the two happen not to have diverged yet.
export type RecallPayload = RecallResult;

// Both key arguments are optional and at least one is required. The singular
// exists for the caller that sends one string *instead of* the list, so requiring
// the list would make that call invalid; the schema cannot express "one of", so
// the invariant is data and is checked at the call.
export const RECALL_KEY_ARGS = ["entity_keys", "entity_key"] as const;

export interface RecallArgs {
  readonly entity_keys?: readonly string[];
  readonly entity_key?: string;
  // Every read takes one, rather than an as-of read being a tool of its own.
  readonly as_of?: string;
  // For the read log, which is #732's. Defaulted rather than required: an
  // unattributed read is still worth logging.
  readonly caller_kind?: string;
  readonly caller_id?: string;
}

// Two points this contract does not settle.
//
// `dropped` diverges from #732's grooming note, which reads three integers where
// #729 asks for the count *and why*.
//
// Per-entity counts of open questions are the one ranking input the spec names
// that no field here carries. Nearly derivable -- Gaps plus handed_off Verdicts,
// grouped by subject_entities -- except the per-key cap truncates precisely the
// entities the count exists to surface, and dropped is aggregated across the read
// rather than per key. Both fixes add a key; the ranking is the harness's, so the
// choice is the harness's.

// One row holding the whole mapping. It validates rather than casting, because a
// cast would let a drifted payload through as a RecallResult of undefined fields,
// which renders as an entity nobody has looked at -- true of every entity, so
// nothing looks wrong.
export const recallOf = (result: ToolResult): RecallResult | null => {
  if (!result.ok || result.rowCount !== 1 || result.rows.length !== 1) return null;
  const row = result.rows[0];
  if (typeof row !== "object" || row === null) return null;
  return RECALL_RESULT_KEYS.every((key) => key in row) ? (row as RecallResult) : null;
};
