import type { RunSpec } from "./spec.js";

export const TOPOLOGIES = ["single", "fan_out", "swarm"] as const;
export type TopologyId = (typeof TOPOLOGIES)[number];

export interface Assignment {
  role: string;
  task: string;
}

// What the deciding turn produced, reduced to what a topology may read. A
// topology never sees the whole decision: fanning out is not a domain judgement.
export interface Selection {
  worker: string | null;
  task: string;
}

export interface Round {
  assigned: number;
}

// Who runs next, and whether this shape of run has gone quiet. Termination stays
// the workflow's: a topology contributes a reason, it does not own the ending.
export interface Topology {
  readonly id: TopologyId;
  assign(selection: Selection, spec: RunSpec): Assignment[];
  settled(rounds: readonly Round[]): boolean;
}

// One role and its tools. A single arch declares no workers, so an assignment
// would name a role the roster does not hold.
const single: Topology = {
  id: "single",
  assign: () => [],
  settled: () => false,
};

// The decider names one worker and the arch caps how many may run. Fanning over
// a workflow's own frontier rather than one name is that workflow's to add.
const fanOut: Topology = {
  id: "fan_out",
  assign: (selection, spec) => {
    if (selection.worker === null || !(selection.worker in spec.roles.workers)) return [];
    return [{ role: selection.worker, task: selection.task }].slice(0, spec.dispatch.max_workers);
  },
  settled: () => false,
};

// Every peer each round, whatever the coordinating turn named: there is no lead
// deciding who acts, only a round that ends when nobody has anything to add.
const QUIET_ROUNDS = 2;

const swarm: Topology = {
  id: "swarm",
  assign: (selection, spec) =>
    Object.keys(spec.roles.workers)
      .sort()
      .slice(0, spec.dispatch.max_workers)
      .map((role) => ({ role, task: selection.task })),
  // Quiescence, not consensus: a swarm that has stopped producing work has
  // finished whether or not it agrees, and saying so beats running on.
  settled: (rounds) =>
    rounds.length >= QUIET_ROUNDS && rounds.slice(-QUIET_ROUNDS).every((round) => round.assigned === 0),
};

const BUILT: Record<TopologyId, Topology> = { single, fan_out: fanOut, swarm };

export class UnknownTopology extends Error {}

export function topologyFor(id: string): Topology {
  const held = BUILT[id as TopologyId];
  if (held === undefined) {
    throw new UnknownTopology(`no topology ${id}; the arch may declare ${TOPOLOGIES.join(", ")}`);
  }
  return held;
}
