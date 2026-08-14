import { openCheckpoint, type OpenCheckpoint } from "../../contracts/events.js";
import { fold, type HuntEvent } from "./ledger.js";
import type { HuntOutcome, HuntState, HuntStatus, Hypothesis, HypothesisStatus } from "./types.js";

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
  };
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
