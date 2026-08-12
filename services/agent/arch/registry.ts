import { fileURLToPath } from "node:url";
import type { RunKind } from "../contracts/events.js";
import { SpecError, type Owned } from "../core/spec.js";

// What a run kind runs, and what its workflow can act on. Adding an agent type is
// an arch file plus an entry here, never a change to the loop.
export interface ArchEntry {
  arch: string;
  actions: readonly string[];
  halts: readonly string[];
  // Sections of the playbook and config this workflow reads. The loader accepts
  // them and looks no further: their meaning is the workflow's to give.
  owned?: Owned;
}

const REGISTERED: Partial<Record<RunKind, ArchEntry>> = {
  hunt: {
    arch: packaged("threathunt.yaml"),
    actions: ["INVESTIGATE", "EXPAND", "PIVOT", "DEEPEN", "ABANDON", "VALIDATE", "CHECKPOINT", "CONCLUDE", "HANDOFF_IR"],
    halts: ["CONCLUDE"],
    owned: { playbook: ["hypotheses", "attack_techniques", "data_domains"], config: ["enrichment", "checkpoints", "hypothesis_loop"] },
  },
  investigate: { arch: packaged("investigate.yaml"), actions: ["EXAMINE", "CONCLUDE"], halts: ["CONCLUDE"] },
  // No actions: nothing emits one. A step ends when its agent answers, and the run
  // ends when the list does, so there is no verb for a model to choose or to halt on.
  compose: { arch: packaged("compose.yaml"), actions: [], halts: [] },
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
