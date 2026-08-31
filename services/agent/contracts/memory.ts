// The recall contract (#729): the one shape Python returns and TypeScript
// journals, agreed before either side built against it. A mismatch here fails as
// "no history", which is the same shape as every other silent failure in this
// area, so it is pinned before code exists rather than after.
//
// There is one shape, carried two ways. The run-start read journals it verbatim
// as the recall event payload; a mid-run tool call carries the same object as the
// single row of a ToolResult. Not two types that happen to agree -- a parallel
// payload would be a second contract, and the second one is the one that drifts.
//
// The Python half is core/memory/recall_contract.py, and
// tests/unit/_ratchets/test_recall_contract_agrees.py fails when the two drift.
// That ratchet is what makes this an agreement rather than two documents.
//
// Nothing imports this yet. #732 lands the tool, #731 the rows it reads, and the
// harness's recall call lands the event. The point of arriving first is that
// three slices join to one declaration instead of three guesses.

import type { ToolResult } from "./tool.js";

export const RECALL_TOOL = "recall_entity";

// What the arch asks for, not what this deployment calls it (core/spec.ts,
// RoleSpec.needs). A capability nothing provides is dropped rather than fatal, so
// a role may ask for recall in a deployment that has no memory yet.
export const RECALL_CAPABILITY = "entity_recall";

// Which caller gets which tool, empties included: a role granted nothing is a
// decision here and reads as an oversight when it is left out.
//
// Keyed by the role names arch/threathunt.yaml actually declares, not by a class
// called "worker" that appears in no file. The arch nests the three under
// roles.workers, and a grant is written on each.
//
// Workers get exact lookups. The lead does not -- it never queries, it reads a
// digest -- and narrative search, the lead's alone, is a later change that ships
// no tool here. The critic already holds nothing.
//
// The run-start read appears in no row: it is not a tool call, so it needs no
// grant. Which is also why only it needs an event kind, while a mid-run call is
// journaled as an ordinary dispatch.
//
// One tool, not three. `prior_investigations` and `attribution` are deferrable:
// attribution is a Verdict with an actor in it, and an as-of parameter belongs on
// every read rather than being a tool of its own. Each extra tool costs prompt
// surface, a grant per role, and a choice the model can get wrong.
export const RECALL_GRANTS = {
  lead: [],
  critic: [],
  threat_hunter: [RECALL_CAPABILITY],
  network_analyst: [RECALL_CAPABILITY],
  threat_intel: [RECALL_CAPABILITY],
} as const;

// Who concluded, as distinct from what the source is. Two axes, because telemetry
// observes and a feed asserts but neither concludes -- so an ordered list of the
// four could never place two of them on a Verdict at all.
export const TRUST_LEVELS = ["analyst", "agent"] as const;
export type Trust = (typeof TRUST_LEVELS)[number];

// What a source *is*. `not_evidence` on a Verdict is a defect rather than a weak
// row: citing a rule catalogue as corroboration is a run treating a lookup as an
// observation. It is representable so that it is visible.
export const SOURCE_TIERS = ["telemetry", "feed", "not_evidence"] as const;
export type SourceTier = (typeof SOURCE_TIERS)[number];

// Three-valued, replacing a flat corroborated list, which cannot express
// direction: a source that weakened a hypothesis and a source that never bore on
// it are not the same row.
export const STANCES = ["supports", "weakens", "neither"] as const;
export type Stance = (typeof STANCES)[number];

// Keyed by kind and id, never by run_id: a run-keyed schema cannot represent the
// Case-authored Verdicts the writer split requires. `analyst` is declared here and
// written by nothing yet -- chat never writes memory, and an analyst thinking
// aloud is not a Verdict.
export const INVESTIGATION_KINDS = ["hunt", "case", "analyst"] as const;
export type InvestigationKind = (typeof INVESTIGATION_KINDS)[number];

// proven and disproven come straight through; inconclusive covers a hypothesis
// that gathered evidence and did not settle; handed_off is terminal for the hunt
// and not an ending of the claim, so it ranks up like a Gap while still carrying
// evidence, a window and sources; false_positive arrives only from a Case closure.
export const VERDICT_OUTCOMES = ["proven", "disproven", "inconclusive", "handed_off", "false_positive"] as const;
export type VerdictOutcome = (typeof VERDICT_OUTCOMES)[number];

// Whether the window was seen or claimed. A retrospective sweep over old archives
// asserts its window; ranking discounts the weaker one, so it has to be able to
// tell them apart.
export const WINDOW_SOURCES = ["observed", "asserted"] as const;
export type WindowSource = (typeof WINDOW_SOURCES)[number];

// ISO-8601 with an offset, both ends inclusive. Separate from a conclusion date
// because a sweep that concluded today about last March is not newly relevant.
export interface ActivityWindow {
  readonly first_seen: string;
  readonly last_seen: string;
}

// Where a row came from, on every row rather than on the envelope: one read
// returns rows from many investigations, and which one concluded a thing is the
// whole reason a later run trusts it.
export interface RecalledProvenance {
  readonly investigation_kind: InvestigationKind;
  readonly investigation_id: string;
  // When the investigation concluded, not when the row was written. The Distil
  // polls, so an investigation that ended Monday can be written Wednesday
  // carrying Monday's date -- inside the freshness predicate, absent from the
  // read that ran on Tuesday. Which is why recall journals its rows.
  readonly concluded_at: string;
}

// What an investigation observed, one row per entity, investigation and source, so
// growth tracks hunts rather than telemetry volume. Never one row per evidence
// record.
export interface RecalledSighting extends RecalledProvenance {
  readonly entity_key: string;
  readonly source_system: string;
  readonly hit_count: number;
  // Aggregated over the evidence in the group. An entity every record naming it
  // could have been named by an adversary cannot clear a branch on its own.
  readonly attacker_influenceable: boolean;
  readonly window: ActivityWindow;
}

// One row per source on a Verdict. source_system is memory's own column and not a
// foreign key into either producer: a hunt-derived Verdict fills it from the
// Ledger's source_system, a Case-derived one from the data_source of its Findings.
// Two vocabularies land in one column, which is why the tier map is keyed twice.
export interface RecalledVerdictSource {
  readonly source_system: string;
  readonly stance: Stance;
  // Stamped at write time, never joined at read time, so an integration removed
  // or recategorised later cannot change how a past Verdict was corroborated.
  readonly source_tier: SourceTier;
}

// What one investigation concluded about one hypothesis.
export interface RecalledVerdict extends RecalledProvenance {
  // Stable, because the prose gets re-worded and a key that moves when someone
  // edits a sentence is not a key.
  readonly hypothesis_id: string;
  readonly statement: string;
  readonly outcome: VerdictOutcome;
  // Prose, and the one field here that reaches no ranking function: model text
  // that sounds confident must not be able to move a priority (ADR 0015). It is
  // carried for a human reading the run back.
  readonly rationale: string;
  // The entities the hypothesis named, typically one to three -- not the 38 to 76
  // its evidence touched, which are mostly shared infrastructure and remain
  // reachable through Sightings as the weaker and truer claim (ADR 0016).
  readonly subject_entities: readonly string[];
  // True when every source on the verdict was something an adversary could have
  // authored. Not per-source: the question a branch-clearing rule asks is whether
  // anything independent was seen at all.
  readonly attacker_influenceable_only: boolean;
  readonly trust: Trust;
  readonly window: ActivityWindow;
  readonly window_source: WindowSource;
  readonly sources: readonly RecalledVerdictSource[];
}

// Why nothing was gathered. A closed set, so the reasons a question went
// unanswered stay apart instead of collapsing into one.
//
// Each value traces to a line of the spec, because a disposition invented here is
// one #731 would write against and nothing would review. `deprioritised` is the
// status map's `parked` arm; `no_evidence_gathered` is the `inconclusive` and
// `active` arms, both of which write a Verdict if evidence was gathered and a Gap
// otherwise, and is also where a `data_starved` run's open questions land, since
// such a run writes normally; `budget_exhausted` is work abandoned for budget and
// the `budget_terminated` run terminal.
//
// Deliberately not `never_dispatched`: a hypothesis that reached `inconclusive`
// with nothing gathered *was* dispatched, and a value naming the dispatch would
// have made those two indistinguishable. Deliberately not a `no_data_source`
// value either -- a tool that could not answer is a Visibility Gap, which
// CONTEXT.md keeps distinct from a Declared Gap on purpose.
export const GAP_DISPOSITIONS = ["deprioritised", "no_evidence_gathered", "budget_exhausted"] as const;
export type GapDisposition = (typeof GAP_DISPOSITIONS)[number];

// How a queried key is matched against a stored one. Pinned rather than
// described, because the two sides normalise in different languages: the rule is
// `defang` then case-fold in workflows/hunt/entities.ts, and Python has to
// reproduce it exactly or an exact join quietly misses.
//
// The exception is the part that breaks silently. An ARN's resource part and an
// AWS key id are case-significant, so folding them makes two different principals
// one key -- and the join still returns rows, just the wrong ones.
export const KEY_CASE_SENSITIVE_TYPES = ["arn", "aws_key"] as const;

// A question an investigation never gathered evidence for. Carries no activity
// window, which is the reason it is not a Verdict with an empty outcome.
//
// Gaps are the common case, not the exception: the committed fixtures leave 14 of
// 18 hypotheses open at terminal. What ranks an entity up is accumulation across
// investigations -- six open questions over four runs is a host nobody has
// finished looking at; one is an ordinary run ending.
export interface RecalledGap extends RecalledProvenance {
  readonly hypothesis_id: string;
  readonly statement: string;
  readonly disposition: GapDisposition;
  readonly reason: string;
  readonly subject_entities: readonly string[];
}

// Why rows are missing, per kind, because the two reasons mean different things to
// a caller. per_key_cap means one entity had more history than its share; overall
// means the read was broad. A total is the sum and is not restated.
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
// records the arch by name and not by version, so a replay resolving them afresh
// would select under today's values against rows chosen under the old ones.
//
// Selection only. The order the rows were *presented* in is a fold and is
// deliberately absent -- the harness's ranking curve may change without
// invalidating a historical Ledger, which is only true while the event carries
// rows and not an order.
export interface RecallRanking {
  // The total order the caps were applied under, as SQL. A LIMIT over a partial
  // order lets Postgres return a different set on identical data, which surfaces
  // as a replay diff rather than an error, so ties break on the primary key.
  readonly order: string;
  // Applied as a LATERAL and before the overall cap. A plain trailing LIMIT lets
  // one entity present in every hunt -- a resolver, a proxy -- consume the whole
  // budget, which makes memory less useful the more it holds.
  readonly per_key_cap: number;
  readonly overall_cap: number;
}

// One read of episodic memory. Journaled verbatim as the recall event payload at
// run start, and carried as ToolResult.rows[0] when a worker calls the tool
// mid-run.
//
// No field is optional and no list is nullable: an empty list means
// known-to-be-none, and there is no unknown state to represent. An entity with no
// history is empty lists and zeros, never an error.
// Named as a value and not only as a type, so recallOf can check for them and the
// ratchet can compare them against Python's. A type alone is invisible at runtime,
// which is where the drift arrives.
export const RECALL_RESULT_KEYS = [
  "keys",
  "as_of",
  "sightings",
  "verdicts",
  "gaps",
  "dropped",
  "ranking",
] as const;

export interface RecallResult {
  // Normalised, so a key differing only by case or defanging is the same key. The
  // keys as queried, not as asked for: only Python writes an Entity Key, and the
  // TypeScript extractor's output travels as candidate data.
  readonly keys: readonly string[];
  // The freshness filter that ran (`concluded_at <= as_of`). A filter, and not a
  // substitute for journaling the rows -- see RecalledProvenance.concluded_at.
  readonly as_of: string;
  readonly sightings: readonly RecalledSighting[];
  readonly verdicts: readonly RecalledVerdict[];
  readonly gaps: readonly RecalledGap[];
  readonly dropped: RecallDropped;
  readonly ranking: RecallRanking;
}

// The event payload is the result. Named separately because the two carriers are
// read by different code and an alias says they cannot diverge, where a copied
// interface would only say they happen not to have yet.
export type RecallPayload = RecallResult;

// What the tool accepts. entity_keys is the contract; a singular entity_key is
// wrapped, because a model given a list parameter will sometimes send one string.
//
// `limit` is not in the signature and is not honoured: tools_router injects it
// into every backend call from the harness's bounds, so the handler has to take
// an args mapping and ignore it. The caps here are memory's own and are reported
// in `ranking`; a bound that silently replaced them would make what a run
// remembered depend on a per-tool row ceiling.
export interface RecallArgs {
  readonly entity_keys: readonly string[];
  readonly entity_key?: string;
  // Defaults to now. Every read takes one, rather than an as-of read being a tool
  // of its own.
  readonly as_of?: string;
  // For the read log, which exists for audit and is the only thing that makes "we
  // can see what it knew" true for a caller with no Ledger. Default `unknown`
  // rather than required: an unattributed read is still worth logging.
  readonly caller_kind?: string;
  readonly caller_id?: string;
}

// Two points this contract does not settle, recorded here rather than in a thread
// because a contract's unresolved edges are part of it.
//
// `dropped` diverges from #732's grooming note, which reads `dropped {sightings,
// verdicts, gaps}` and would have an implementer write three integers. #729 asks
// for "the dropped count and why", and one integer cannot carry the why, so the
// leaf is a mapping of the two cap reasons.
//
// Per-entity counts of open questions are what the spec's ranking-inputs section
// owes this side, and they are the one item that section names which no field here
// carries. They are *nearly* derivable -- open questions are Gaps plus
// `handed_off` Verdicts, grouped by subject_entities -- but the per-key cap
// truncates precisely the entities the count exists to surface, and `dropped` is
// aggregated across the read rather than per key, so a caller cannot tell 20 from
// 60. Resolving it means either a count taken before the caps or per-key drop
// attribution. Flagged rather than chosen: the ranking is the harness's, so which
// of the two it wants is the harness's to say.

// The mid-run carrier, narrowed. One row holding the whole mapping, so
// tools_router does not slice the inner lists into rows of their own and lose
// which list each came from.
//
// It validates rather than casting, because the failure this contract exists to
// prevent is a shape mismatch that reads as "no history". A cast would let a
// drifted payload through as a RecallResult with undefined fields, which renders
// as an entity nobody has looked at -- true of every entity, so nothing looks
// wrong. Returning null makes the drift a case the caller has to answer for.
export const recallOf = (result: ToolResult): RecallResult | null => {
  if (!result.ok || result.rowCount !== 1 || result.rows.length !== 1) return null;
  const row = result.rows[0];
  if (typeof row !== "object" || row === null) return null;
  // rowCount is the adapter's word for how many rows there are; the keys are the
  // only evidence of what they hold.
  return RECALL_RESULT_KEYS.every((key) => key in row) ? (row as RecallResult) : null;
};
