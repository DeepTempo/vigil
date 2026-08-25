import { describe, expect, it } from "vitest";
import { topologyFor, TOPOLOGIES, UnknownTopology, type Round } from "../../core/topology.js";
import type { RunSpec } from "../../core/spec.js";

function specWith(workers: string[], max_workers = 4): RunSpec {
  return {
    dispatch: { topology: "fan_out", mode: "parallel", fan_out_over: "questions", max_workers },
    roles: { workers: Object.fromEntries(workers.map((id) => [id, {}])) },
  } as unknown as RunSpec;
}

const ROSTER = specWith(["network_analyst", "threat_intel", "threat_hunter"]);
const PICKED = { worker: "threat_intel", task: "check the observable" };

function quiet(count: number): Round[] {
  return Array.from({ length: count }, () => ({ assigned: 0 }));
}

describe("the arch selects a topology", () => {
  it.each(TOPOLOGIES)("resolves %s", (id) => {
    expect(topologyFor(id).id).toBe(id);
  });

  it("refuses one nothing implements, and says what it may say instead", () => {
    expect(() => topologyFor("hive")).toThrow(UnknownTopology);
    expect(() => topologyFor("hive")).toThrow(/single, fan_out, swarm/);
  });
});

describe("single dispatches to nobody", () => {
  it("assigns nothing however the decider chose", () => {
    expect(topologyFor("single").assign(PICKED, ROSTER)).toEqual([]);
  });

  it("never settles on its own: the workflow owns its ending", () => {
    expect(topologyFor("single").settled(quiet(50))).toBe(false);
  });
});

describe("fan_out follows the decider", () => {
  const fanOut = topologyFor("fan_out");

  it("assigns the worker that was named", () => {
    expect(fanOut.assign(PICKED, ROSTER)).toEqual([{ role: "threat_intel", task: "check the observable" }]);
  });

  it("assigns nobody when the decider named nobody", () => {
    expect(fanOut.assign({ worker: null, task: "think" }, ROSTER)).toEqual([]);
  });

  it("refuses a name the roster does not hold rather than inventing a worker", () => {
    expect(fanOut.assign({ worker: "made_up", task: "go" }, ROSTER)).toEqual([]);
  });

  it("respects max_workers as a ceiling", () => {
    expect(fanOut.assign(PICKED, specWith(["threat_intel"], 0))).toEqual([]);
  });

  it("never settles on its own", () => {
    expect(fanOut.settled(quiet(50))).toBe(false);
  });
});

describe("swarm runs peers, not a chosen one", () => {
  const swarm = topologyFor("swarm");

  it("assigns every peer regardless of who was named", () => {
    expect(swarm.assign(PICKED, ROSTER).map((one) => one.role)).toEqual([
      "network_analyst",
      "threat_hunter",
      "threat_intel",
    ]);
  });

  it("assigns the same peers when nobody was named, because nobody decides", () => {
    const named = swarm.assign(PICKED, ROSTER);
    expect(swarm.assign({ worker: null, task: "check the observable" }, ROSTER)).toEqual(named);
  });

  it("holds max_workers as a ceiling on how wide a round goes", () => {
    expect(swarm.assign(PICKED, specWith(["a", "b", "c"], 2))).toHaveLength(2);
  });

  it("settles when the swarm has gone quiet", () => {
    expect(swarm.settled(quiet(2))).toBe(true);
  });

  it("does not settle on one quiet round, which is a pause and not an ending", () => {
    expect(swarm.settled(quiet(1))).toBe(false);
  });

  it("does not settle while a round is still producing work", () => {
    expect(swarm.settled([{ assigned: 0 }, { assigned: 3 }])).toBe(false);
  });

  it("settles on quiescence rather than on agreement, so a split swarm still ends", () => {
    expect(swarm.settled([{ assigned: 3 }, { assigned: 0 }, { assigned: 0 }])).toBe(true);
  });
});

describe("adding a topology needs no change to the loader or the loop", () => {
  it("every declared topology satisfies the same port", () => {
    for (const id of TOPOLOGIES) {
      const held = topologyFor(id);
      expect(typeof held.assign).toBe("function");
      expect(typeof held.settled).toBe("function");
      expect(held.assign(PICKED, ROSTER).every((one) => one.role in ROSTER.roles.workers)).toBe(true);
    }
  });
});
