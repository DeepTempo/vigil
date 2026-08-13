// One of the four Phase-0 contracts. Consumed by the resume path, deployment,
// and the Python backend, which enqueues plain JSON and writes no ledger.

import type { RunKind } from "./events.js";

export const JOB_SCHEMA_VERSION = 1;

// No colon: BullMQ's Node library refuses a queue name containing one, while
// its Python library accepts it and writes the keys anyway. Keys are bull:agent-runs:*.
export const RUN_QUEUE = "agent-runs";

interface JobBase {
  schema_version: number;
  run_id: string;
  run_kind: RunKind;
  tenant_id: string | null;
  enqueued_at: string;
  enqueued_by: string;
}

// References rather than resolved content: the worker resolves them and journals
// the result into the run event, so Python never writes the ledger (D2).
export interface StartRequest {
  arch: string;
  playbook: string;
  config: string;
  prompt: string;
  overrides?: Record<string, unknown>;
}

// A resume carries no request, so a resume path that read one would not compile.
// That is the "resumable from the payload plus the ledger" guarantee, as a type.
export type RunJob =
  | (JobBase & { reason: "start"; request: StartRequest })
  | (JobBase & { reason: "resume" });

// jobId = run_id for a start, so a double POST dedupes in BullMQ rather than in
// application code.
//
// A resume takes a distinct id every time, and deliberately does not dedupe. A
// parked run's seq never advances -- nothing is appended while it waits -- so an
// id derived from the ledger position would be identical on every check, and the
// queue would drop all of them after the first: the run would be looked at once
// and then wait forever, which is the bug the sweeper exists to fix. Nor can
// retention be leaned on, because one *failed* resume would then hold that id and
// wedge the run permanently. Run-level exclusion is the lease's, held in the same
// statement that discovers the run is due, which is a stronger place for it.
export function jobIdFor(job: RunJob, attempt: string): string {
  return job.reason === "start" ? job.run_id : `${job.run_id}:${attempt}`;
}
