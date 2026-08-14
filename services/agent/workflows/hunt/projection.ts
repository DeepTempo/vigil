import { openCheckpoint, type OpenCheckpoint } from "../../contracts/events.js";
import { fold, type HuntEvent } from "./ledger.js";
import { renderReport, type HuntReport } from "./report.js";
import type { Handoff, HuntOutcome, HuntState, HuntStatus, Hypothesis, HypothesisStatus } from "./types.js";

// What a reader outside this process is told about a hunt. A hunt has no steps to
// report progress against, so what it has tested and how each belief stands is it.
export interface HuntProjection {
  run_id: string;
  status: HuntStatus;
  outcome: HuntOutcome | null;
  reason: string;
  iteration: number;
  cost_usd: number;
  hypotheses: HypothesisStanding[];
  evidence_count: number;
  open_checkpoint: OpenCheckpoint | null;
  // The deliverable, null until the hunt writes one. Rendered here because the
  // renderer is this side's: a reader that formatted the report itself would be a
  // second opinion about what a hunt found.
  report: HuntReport | null;
  report_markdown: string | null;
  // What the hunt asked someone else to take on, each carrying its own case file.
  handoffs: Handoff[];
}

export interface HypothesisStanding {
  hypothesis_id: string;
  statement: string;
  status: HypothesisStatus;
  attack_technique: string | null;
  resolution_reason: string | null;
}

export function huntProjection(runId: string, events: readonly HuntEvent[]): HuntProjection {
  const view = fold(events);
  const answered = new Set(view.resolutions.map((resolution) => resolution.checkpoint_id));
  const open = [...view.checkpoints.values()].find((checkpoint) => !answered.has(checkpoint.checkpoint_id));
  const report = reportIn(events);

  return {
    run_id: runId,
    status: view.hunt.status,
    outcome: view.hunt.outcome,
    reason: why(view.hunt),
    iteration: view.hunt.iteration,
    cost_usd: view.hunt.cost_usd,
    hypotheses: [...view.hypotheses.values()].map(standing),
    evidence_count: view.evidence.size,
    open_checkpoint: open === undefined ? null : openCheckpoint(open),
    report,
    report_markdown: report === null ? null : renderReport(report),
    handoffs: events.filter((event) => event.kind === "handoff").map((event) => event.payload as Handoff),
  };
}

// The last one written. A run that resumed past its own terminal wrote a second,
// and the later one is the report of the hunt that actually happened.
function reportIn(events: readonly HuntEvent[]): HuntReport | null {
  const finalized = events.filter((event) => event.kind === "finalize");
  const last = finalized.at(-1);
  return last === undefined ? null : (last.payload as HuntReport);
}

// A parked hunt is asked why it stopped, a terminal one why it ended, and the two
// are different fields: a hunt that resumed and later ended still holds both.
function why(hunt: HuntState): string {
  return (hunt.status === "terminal" ? hunt.termination_reason : hunt.parked_reason) ?? "";
}

function standing(hypothesis: Hypothesis): HypothesisStanding {
  const { hypothesis_id, statement, status, attack_technique, resolution_reason } = hypothesis;
  return { hypothesis_id, statement, status, attack_technique, resolution_reason };
}
