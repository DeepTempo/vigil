import type { SpendPayload } from "../../contracts/budget.js";
import type { AgentEvent, CheckpointPayload, ResolutionPayload, TerminalPayload } from "../../contracts/events.js";
import type { DecisionPayload, FindingPayload, LeadKinds } from "./workflow.js";

// What a reader outside this process is told about a run. Deliberately not the
// ledger: the events are the record and their shape stays ours to change, so a
// caller reads what a run has decided rather than how it was written down.
export interface LeadProjection {
  run_id: string;
  status: "running" | "waiting_approval" | "terminal";
  outcome: TerminalPayload["outcome"] | null;
  reason: string;
  iterations: number;
  dispatched: number;
  cost_usd: number | null;
  decisions: DecisionPayload[];
  findings: FindingPayload[];
  // The one a resolution must answer for the run to go on. Null while nothing is
  // parked, which is the only question a supervisor actually asks of a run.
  open_checkpoint: OpenCheckpoint | null;
}

export interface OpenCheckpoint {
  checkpoint_id: string;
  checkpoint_class: string;
  question: string;
  raised_at: string;
  context: Record<string, unknown>;
}

export function leadProjection(runId: string, events: readonly AgentEvent<LeadKinds>[]): LeadProjection {
  const decisions: DecisionPayload[] = [];
  const findings: FindingPayload[] = [];
  const raised: CheckpointPayload[] = [];
  const answered = new Set<string>();
  let dispatched = 0;
  let terminal: TerminalPayload | null = null;
  // Null until a gateway prices something. A run that has spent nothing yet and
  // one whose provider reports no cost are different claims.
  let cost: number | null = null;

  for (const event of events) {
    switch (event.kind) {
      case "decision":
        decisions.push(event.payload as DecisionPayload);
        break;
      case "finding":
        findings.push(event.payload as FindingPayload);
        break;
      case "dispatch":
        dispatched += 1;
        break;
      case "checkpoint":
        raised.push(event.payload as CheckpointPayload);
        break;
      case "resolution":
        answered.add((event.payload as ResolutionPayload).checkpoint_id);
        break;
      case "spend": {
        const spent = (event.payload as SpendPayload).cost_usd;
        if (spent !== null) cost = (cost ?? 0) + spent;
        break;
      }
      case "terminal":
        terminal = event.payload as TerminalPayload;
        break;
    }
  }

  const open = raised.find((checkpoint) => !answered.has(checkpoint.checkpoint_id)) ?? null;
  return {
    run_id: runId,
    status: terminal !== null ? "terminal" : open !== null ? "waiting_approval" : "running",
    outcome: terminal?.outcome ?? null,
    reason: terminal?.reason ?? "",
    iterations: decisions.length,
    dispatched,
    cost_usd: cost,
    decisions,
    findings,
    open_checkpoint: open === null ? null : opened(open),
  };
}

function opened(checkpoint: CheckpointPayload): OpenCheckpoint {
  const { checkpoint_id, checkpoint_class, question, raised_at } = checkpoint;
  return { checkpoint_id, checkpoint_class, question, raised_at, context: checkpoint.context ?? {} };
}
