import { fileURLToPath } from "node:url";
import type { AgentEvent, RunKind } from "../contracts/events.js";
import type { Notes } from "../core/memory.js";
import type { State } from "../core/seams.js";
import { SpecError, type Owned } from "../core/spec.js";
import type { HuntKinds } from "../workflows/hunt/ledger.js";
import { huntProjection } from "../workflows/hunt/projection.js";
import { huntNotes } from "../workflows/hunt/recall.js";
import { leadProjection } from "../workflows/lead/projection.js";
import type { LeadKinds } from "../workflows/lead/workflow.js";

// Which loop drives a kind, and what its workflow may act on. Named here rather
// than switched on in the worker: an agent type is a file and an entry, not a branch.
export type WorkflowId = "lead" | "compose" | "hunt";

export interface ArchEntry {
  arch: string;
  workflow: WorkflowId;
  actions: readonly string[];
  halts: readonly string[];
  // Sections of the playbook and config this workflow reads. The loader accepts
  // them and looks no further: their meaning is the workflow's to give.
  owned?: Owned;
  // How a later run recalls a finished one of this kind. Absent means it carries
  // nothing forward, which is the honest default rather than a summary of events.
  notes?: (state: State, runId: string) => Notes;
  // What a reader outside this process is told about a run of this kind. Absent
  // means there is nothing to report but the terminal the ledger already carries.
  projection?: (runId: string, events: readonly AgentEvent<Record<never, never>>[]) => unknown;
}

const REGISTERED: Partial<Record<RunKind, ArchEntry>> = {
  hunt: {
    arch: packaged("threathunt.yaml"),
    workflow: "hunt",
    actions: ["INVESTIGATE", "EXPAND", "PIVOT", "DEEPEN", "ABANDON", "VALIDATE", "CHECKPOINT", "CONCLUDE", "HANDOFF_IR"],
    halts: ["CONCLUDE"],
    owned: { playbook: ["hypotheses", "attack_techniques", "data_domains"], config: ["enrichment", "checkpoints", "hypothesis_loop"] },
    // Retyped here because this entry is the one place that already knows the
    // kind, the same trade the worker makes when it hands a ledger to a workflow.
    notes: (state, runId) => huntNotes(state as unknown as State<HuntKinds>, runId),
    projection: (runId, events) => huntProjection(runId, events as readonly AgentEvent<HuntKinds>[]),
  },
  investigate: {
    arch: packaged("investigate.yaml"),
    workflow: "lead",
    actions: ["EXAMINE", "CONCLUDE"],
    halts: ["CONCLUDE"],
    projection: (runId, events) => leadProjection(runId, events as readonly AgentEvent<LeadKinds>[]),
  },
  // No actions: nothing emits one. A step ends when its agent answers, and the run
  // ends when the list does, so there is no verb for a model to choose or to halt on.
  compose: { arch: packaged("compose.yaml"), workflow: "compose", actions: [], halts: [] },
  // No actions: the lead answers in prose, so there is no emission to constrain.
  // Served over SSE by serve.ts rather than the queue, so drive() never sees it.
  chat: { arch: packaged("chat.yaml"), workflow: "lead", actions: [], halts: [] },
};

// Resolved against the package rather than the cwd: the arch files ship with the
// worker, so a run started from any directory finds the same ones.
function packaged(file: string): string {
  return fileURLToPath(new URL(`./${file}`, import.meta.url));
}

export function archFor(kind: RunKind): ArchEntry {
  const entry = REGISTERED[kind];
  if (entry === undefined) {
    throw new SpecError(`no architecture is registered for run_kind ${kind}; registered: ${registeredKinds().join(", ")}`);
  }
  return entry;
}

export function registeredKinds(): RunKind[] {
  return (Object.keys(REGISTERED) as RunKind[]).sort();
}
