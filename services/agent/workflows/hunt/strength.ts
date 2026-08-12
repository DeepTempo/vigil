import type { Projection } from "./ledger.js";
import type { Verdicts } from "./config.js";
import type { DispatchRecord, EvidenceRecord, EvidenceStrength, LinkRelation } from "./types.js";

export const NULL_CHECK_PROVENANCE = "null_check";
export const CRITIC_SOURCE_SYSTEM = "critic";
export const UNDECLARED_SOURCE = "undeclared";

// A blind spot an operator declared rather than one a tool discovered: "we have
// no EDR on that subnet" is a fact about visibility that no query would ever
export const OPERATOR_GAP_PROVENANCE = "operator_gap";

// The one gap reader over evidence, which is why a new kind of blind spot
// updates exactly this function and the count below it.
export function isGap(record: EvidenceRecord): boolean {
  return record.provenance === "tool_failure" || record.provenance === OPERATOR_GAP_PROVENANCE;
}

// What went unanswered, not how many times it failed: three retries of one query
// are one blind spot. The intent is the key when no lead owns the dispatch.
function gapKey(dispatch: DispatchRecord): string {
  return dispatch.question_id ?? dispatch.query_intent;
}

// A gap belongs to the hypothesis the dispatch was serving, and stops being a
// gap once the same question is answered — being unable to look once is not a
export function openGaps(projection: Projection, hypothesisId: string): number {
  const answered = new Set<string>();
  const unanswered = new Set<string>();

  for (const dispatch of projection.dispatches.values()) {
    if (dispatch.target_hypothesis_id !== hypothesisId) continue;
    if (dispatch.status === "complete") answered.add(gapKey(dispatch));
    if (dispatch.status === "failed") unanswered.add(gapKey(dispatch));
  }

  for (const record of projection.evidence.values()) {
    if (record.provenance !== OPERATOR_GAP_PROVENANCE) continue;
    if (record.payload["hypothesis_id"] !== hypothesisId) continue;
    unanswered.add(record.summary);
  }

  return [...unanswered].filter((key) => !answered.has(key)).length;
}

// Read off the appended record rather than the critic's return value, so a
// verdict rests on the ledger and replays to the same answer.
function nullChecksFor(projection: Projection, hypothesisId: string): EvidenceRecord[] {
  return [...projection.evidence.values()].filter(
    (record) => record.provenance === NULL_CHECK_PROVENANCE && record.payload["hypothesis_id"] === hypothesisId,
  );
}

// A verdict rests on a *current* argument. The latest null check must have
// stood, and it must have been argued against everything now linked: an earlier
function survivedDisconfirmation(projection: Projection, hypothesisId: string, linked: readonly string[]): boolean {
  const checks = nullChecksFor(projection, hypothesisId);
  const latest = checks[checks.length - 1];
  if (latest === undefined || latest.payload["survives"] !== true) return false;

  const argued = new Set((latest.payload["argued_evidence_ids"] as string[] | undefined) ?? []);
  return linked.every((evidenceId) => argued.has(evidenceId));
}

export function evidenceStrength(projection: Projection, hypothesisId: string): EvidenceStrength {
  const linked = (relation: LinkRelation): EvidenceRecord[] =>
    projection.links
      .filter((link) => link.hypothesis_id === hypothesisId && link.relation === relation)
      .map((link) => projection.evidence.get(link.evidence_id))
      .filter((record): record is EvidenceRecord => record !== undefined);

  const supporting = linked("supports");
  const contradicting = linked("weakens");
  const allLinked = [...supporting, ...contradicting].map((record) => record.evidence_id);

  return {
    // Distinct systems: ten records out of one tool are one system agreeing with
    // itself, which is not corroboration.
    corroborating_sources: new Set(supporting.map((record) => record.source_system)).size,
    contradicting_records: contradicting.length,
    open_gaps: openGaps(projection, hypothesisId),
    // Vacuously true with no support at all, which is the fail-closed answer.
    attacker_influenceable_only: supporting.every((record) => record.attacker_influenceable),
    survived_disconfirmation: survivedDisconfirmation(projection, hypothesisId, allLinked),
  };
}

// Every predicate a verdict fails, so "not proven" is never a bare no.
export function unmetPredicates(strength: EvidenceStrength, verdicts: Verdicts): string[] {
  const unmet: string[] = [];
  if (!strength.survived_disconfirmation) {
    unmet.push("the strongest benign explanation was not ruled out against everything now linked to it");
  }
  if (strength.corroborating_sources < verdicts.min_corroborating_sources) {
    unmet.push(
      `${strength.corroborating_sources} corroborating source system(s), ${verdicts.min_corroborating_sources} required`,
    );
  }
  if (strength.attacker_influenceable_only) {
    unmet.push("every supporting record sits in a field an adversary could have written");
  }
  if (strength.open_gaps >= verdicts.gap_lock_threshold) {
    unmet.push(`${strength.open_gaps} open visibility gap(s) bear on it`);
  }
  return unmet;
}

export const pairKey = (evidenceId: string, hypothesisId: string) => `${evidenceId} ${hypothesisId}`;

// Observations the lead has seen and not yet ruled on, against every hypothesis
// still standing. Scoped to the latest iteration because that is what it can see.
export function unclassified(projection: Projection): { evidence_id: string; hypothesis_id: string }[] {
  const active = [...projection.hypotheses.values()].filter((hypothesis) => hypothesis.status === "active");
  const observed = [...projection.evidence.values()].filter((record) => record.provenance === "worker");
  if (active.length === 0 || observed.length === 0) return [];

  const latest = Math.max(...observed.map((record) => record.iteration));
  const linked = new Set(projection.links.map((link) => pairKey(link.evidence_id, link.hypothesis_id)));
  return observed
    .filter((record) => record.iteration === latest)
    .flatMap((record) => active.map((hypothesis) => ({ evidence_id: record.evidence_id, hypothesis_id: hypothesis.hypothesis_id })))
    .filter((pair) => !linked.has(pairKey(pair.evidence_id, pair.hypothesis_id)));
}

// What the hunt never ruled on at all. Distinct from unclassified(), which is
// scoped to active hypotheses: by report time the terminal coercion resolved them.
export function unruledObservations(projection: Projection): number {
  const linked = new Set(projection.links.map((link) => link.evidence_id));
  return [...projection.evidence.values()].filter(
    (record) => record.provenance === "worker" && !linked.has(record.evidence_id),
  ).length;
}
