import { scrub } from "../../core/security.js";
import type { Digest, EntityView, EvidenceView, HypothesisView } from "./types.js";

// The digest as the lead reads it: buildDigest decides what is in it, this only
// how it is written. Evidence carries its id, because the lead is asked to cite them.
const EVIDENCE_CAP = 4_000;

// One delimited shape for anything a model reads as evidence, expansions included:
// a raw payload arriving undelimited would read as the digest's own voice.
function evidenceBlock(id: string, body: string): string {
  return `<vigil:evidence id="${id}">\n${body}\n</vigil:evidence>`;
}

function section(heading: string, body: string): string {
  return body.trim() === "" ? "" : `## ${heading}\n${body.trim()}`;
}

function hypothesis(view: HypothesisView): string {
  return `- ${view.hypothesis_id} (${view.status}): ${view.statement}`;
}

function evidence(view: EvidenceView): string {
  const body = scrub(`${view.summary}\n${view.why_notable}`, EVIDENCE_CAP);
  // instruction_like is stated rather than acted on: the lead is told the text
  // reads like direction, and the block is what says it is still only data.
  const flagged = view.instruction_like ? ' instruction_like="true"' : "";
  return [
    `<vigil:evidence id="${view.evidence_id}" source="${view.source_system}" salience="${view.salience}"${flagged}>`,
    body,
    `</vigil:evidence>`,
  ].join("\n");
}

function entity(view: EntityView): string {
  const suppressed = view.suppressed === true ? ", called benign by an operator" : "";
  return `- ${view.type}:${view.value} (seen ${view.count}x${suppressed})`;
}

function weakening(weakens: Digest["weakens"]): string {
  const entries = Object.entries(weakens).filter(([, views]) => views.length > 0);
  if (entries.length === 0) return "Nothing yet weakens any hypothesis, which means the hunt has looked one way.";
  return entries.map(([id, views]) => `Against ${id}:\n${views.map(evidence).join("\n")}`).join("\n\n");
}

export function renderDigest(digest: Digest): string {
  const budget = `${digest.budget_remaining.iterations} iteration(s), $${digest.budget_remaining.cost_usd.toFixed(2)}`;
  const focus = [digest.focus.entity, digest.focus.hypothesis].filter((part) => part !== null).join(" / ");
  const omitted =
    digest.omitted.count === 0
      ? ""
      : `${digest.omitted.count} routine record(s) compressed out: ${digest.omitted.evidence_ids.join(", ")}`;

  return [
    `# ${digest.hunt_name} — iteration ${digest.iteration}`,
    digest.narrative,
    section("Hypotheses", digest.hypotheses.map(hypothesis).join("\n")),
    section("Recent evidence", digest.recent_evidence.map(evidence).join("\n\n")),
    section("Counter-evidence", weakening(digest.weakens)),
    section("Entities seen", digest.entities.map(entity).join("\n")),
    section("Focus", focus === "" ? "nothing in particular" : focus),
    section("Pivot candidates", digest.pivot_candidates.map(entity).join("\n")),
    section("Compressed", omitted),
    section(
      "Expanded on request",
      digest.expansions.map((one) => evidenceBlock(one.evidence_id, scrub(one.payload, EVIDENCE_CAP))).join("\n\n"),
    ),
    section("Open questions", digest.open_questions.map((one) => `- ${one}`).join("\n")),
    // Last, and named as direction: everything above is data, and the lead is
    // told which is which rather than being left to infer it from position.
    section("Operator directives", digest.directives.map((one) => `- ${one}`).join("\n")),
    section("Notes", digest.notes.map((one) => `- ${one}`).join("\n")),
    section("Budget remaining", budget),
  ]
    .filter((part) => part !== "")
    .join("\n\n");
}
