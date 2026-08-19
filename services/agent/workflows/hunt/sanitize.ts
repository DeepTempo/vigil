import type { WorkerEvidence } from "./types.js";

const SUMMARY_CAP = 2000;
const WHY_CAP = 500;
const PAYLOAD_CAP = 8000;
const QUESTION_CAP = 300;

// The digest wraps evidence in <vigil:evidence> so its content cannot read as
// direction. A record that carries the delimiter itself would close that block.
const DELIMITER = /<\/?vigil:/gi;

// ponytail: keyword heuristic, not a classifier — it will miss paraphrase. It
// only ever raises salience (see salienceFloor), so a miss costs the lead
const INSTRUCTION_LIKE = [
  /\bignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\b/i,
  /\bdisregard\s+(all\s+|any\s+)?(previous|prior|above|earlier|instructions)\b/i,
  /\byou\s+(must|should|need to|are required to)\b/i,
  /\b(system|developer)\s+(prompt|message|instruction)/i,
  /\bnew\s+instructions?\b/i,
  /\b(INVESTIGATE|CONCLUDE|ABANDON|HANDOFF_IR|PIVOT|VALIDATE)\b/,
  /^\s*#{1,6}\s/m,
];

export function looksLikeInstruction(text: string): boolean {
  return INSTRUCTION_LIKE.some((pattern) => pattern.test(text));
}

// Truncation is marked rather than silent: a summary that just stops is
// indistinguishable from a finding that was genuinely that short.
function clamp(text: string, cap: number): string {
  return text.length <= cap ? text : `${text.slice(0, cap)} [truncated ${text.length - cap} chars]`;
}

// Exported for the tool boundary: retrieved web content reaches a worker's
// context before any of this runs on the evidence it emits.
export function scrub(text: string, cap: number): string {
  // Control characters other than tab and newline render as nothing, which is
  // exactly what makes them useful for hiding text from a human reviewer.
  const stripped = text.replace(/[\x00-\x08\x0B-\x1F\x7F]/g, "");
  return clamp(stripped.replace(DELIMITER, "<vigil-"), cap);
}

// Questions render as bare markdown under a heading, with no delimiters around
// them, so a newline is what lets one forge a heading of its own.
export function sanitizeQuestion(text: string): string {
  return scrub(text, QUESTION_CAP).replace(/\s+/g, " ").trim();
}

// The payload reaches the lead verbatim, through both the expand tool and the
// EXPAND action, so its content is scrubbed and not merely capped. Scrubbing the
function scrubPayload(payload: Record<string, unknown>): Record<string, unknown> {
  const text = scrub(JSON.stringify(payload ?? {}), PAYLOAD_CAP);
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return { truncated: text };
  }
}

// Worker output is model text derived from attacker-controlled telemetry. The
// controller applies this to every dispatcher's records, so no implementation
export function sanitize(record: WorkerEvidence): WorkerEvidence {
  const summary = scrub(record.summary, SUMMARY_CAP);
  const why = scrub(record.why_notable, WHY_CAP);

  return {
    ...record,
    summary,
    why_notable: why,
    payload: scrubPayload(record.payload),
    instruction_like: record.instruction_like || looksLikeInstruction(`${summary}\n${why}`),
  };
}
