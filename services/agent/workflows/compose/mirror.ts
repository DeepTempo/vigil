import type { ResolutionPayload, RunOutcome } from "../../contracts/events.js";
import { httpAnswers } from "../../core/answers.js";

// Where a run's progress goes for a human to read, and where a human's answer
// comes back from. The ledger stays the record; this is the copy the UI reads.
export interface PhaseUpdate {
  phase_id: string;
  agent: string;
  name: string;
  order: number;
  status: "running" | "completed" | "failed" | "pending_approval";
  // How a gate on this step was answered. Absent means the step has no gate, so
  // the row keeps whatever it already said.
  approval_state?: "approved" | "rejected";
  output?: Record<string, unknown>;
  error?: string;
  checkpoint_id?: string;
  question?: string;
}

// decisions is the only inbound direction: a human answers over there, and this
// side journals what comes back, so the ledger keeps its single writer.
export interface Mirror {
  // Whether a human can answer through this one. Losing progress does not change
  // a run; a gate nobody can see or answer stops it for good.
  readonly answerable: boolean;
  phase(runId: string, update: PhaseUpdate): Promise<void>;
  terminal(runId: string, outcome: RunOutcome, reason: string, summary: string): Promise<void>;
  decisions(runId: string): Promise<ResolutionPayload[]>;
}

// A run whose progress nobody is watching still runs. Used by tests and by any
// deployment with no backend to mirror into.
export const nullMirror: Mirror = {
  answerable: false,
  phase: async () => {},
  terminal: async () => {},
  decisions: async () => [],
};

export interface MirrorOptions {
  url: string;
  token: string;
  fetch?: typeof globalThis.fetch;
}

export function httpMirror(options: MirrorOptions): Mirror {
  const call = options.fetch ?? globalThis.fetch;
  const base = options.url.replace(/\/$/, "");
  const headers = { "content-type": "application/json", authorization: `Bearer ${options.token}` };

  // Progress is not the run. A backend that cannot take an update must not fail
  // the phase that produced it, so this reports and carries on.
  const post = async (path: string, body: unknown): Promise<void> => {
    try {
      const response = await call(`${base}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
      if (!response.ok) console.warn(`mirror ${path} answered ${response.status}`);
    } catch (error) {
      console.warn(`mirror ${path} failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  return {
    answerable: true,
    phase: (runId, update) => post(`/${encodeURIComponent(runId)}/phases`, update),
    terminal: (runId, outcome, reason, summary) => post(`/${encodeURIComponent(runId)}/terminal`, { outcome, reason, summary }),
    decisions: httpAnswers(options),
  };
}
