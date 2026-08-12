import { afterEach, describe, expect, it, vi } from "vitest";
import type { BudgetLimits } from "../../contracts/budget.js";
import { scoredFrontier } from "../../workflows/hunt/digest.js";
import {
  DEFAULT_TERMINATION,
  DEFAULT_VERDICTS,
  huntSpec,
  type Termination,
} from "../../workflows/hunt/config.js";
import { HuntParked } from "../../workflows/hunt/controller.js";
import { steer } from "../../workflows/hunt/inbox.js";
import { ScriptedDecisionProvider } from "../../workflows/hunt/scripted.js";
import type { Journal } from "../../workflows/hunt/journal.js";
import { buildReport, renderReport } from "../../workflows/hunt/report.js";
import { terminationVerdict } from "../../workflows/hunt/termination.js";
import {
  CONCLUDE,
  controllerFor,
  finalized,
  gapLock,
  huntSpecFor,
  INVESTIGATE,
  newLedger,
  question,
  resolve,
  type SpecOverrides,
} from "../support/hunt.js";

afterEach(() => {
  vi.restoreAllMocks();
});

const CAPPED: BudgetLimits = { max_calls: 1, max_cost_usd: 10, max_wall_ms: 1_800_000 };

describe("the predicate, not the recommendation", () => {
  it("refuses CONCLUDE while a hypothesis is active, without spending a re-prompt", async () => {
    const { ledger } = await newLedger();
    const provider = new ScriptedDecisionProvider([CONCLUDE, CONCLUDE]);
    const controller = controllerFor(ledger, [], { provider });

    const result = await controller.advanceIteration();

    expect(result.hunt_status).toBe("active");
    expect(result.hunt_outcome).toBeNull();
    expect(result.note).toMatch(/CONCLUDE refused: .* is still active/);

    // A refusal is not an invalid emission: the decision stands on the record,
    // and it cost exactly one call.
    expect(ledger.projection.decisions).toHaveLength(1);
    expect(ledger.projection.decisions[0]!.decision.action).toBe("CONCLUDE");
    expect(ledger.projection.decisions[0]!.rejected_attempts).toBeUndefined();
    expect(provider.seenDigests).toHaveLength(1);

    // And the reason reaches the next digest, so the lead can act on it rather
    // than re-emitting the same recommendation.
    await controller.advanceIteration();
    expect(provider.seenDigests[1]!.directives.join(" ")).toMatch(/CONCLUDE refused/);
  });

  it("refuses CONCLUDE when a lead at or above the floor is still open", async () => {
    const { ledger, hypothesisIds } = await newLedger();
    resolve(ledger, hypothesisIds[0]!);
    question(ledger, "who else used this key?", { entity_key: "aws_key:AKIA1", spawned_iteration: 1 });

    const result = await controllerFor(ledger, [CONCLUDE]).advanceIteration();

    expect(result.hunt_status).toBe("active");
    expect(result.note).toMatch(/who else used this key\?/);
    expect(result.note).toMatch(/priority floor of 5/);
  });

  it("completes and auto-parks the sub-floor leads as backlog", async () => {
    const { ledger, hypothesisIds } = await newLedger();
    resolve(ledger, hypothesisIds[0]!);
    // Already covered by a lead a worker took, so it is not novel: below the floor.
    question(ledger, "recheck 10.0.0.9", { entity_key: "ip:10.0.0.9", status: "closed" });
    const parked = question(ledger, "recheck 10.0.0.9 next quarter", { entity_key: "ip:10.0.0.9" });

    const result = await controllerFor(ledger, [CONCLUDE]).advanceIteration();

    expect(result.hunt_outcome).toBe("completed");
    expect(ledger.projection.questions.get(parked)!.status).toBe("parked");
    expect(ledger.projection.questions.get(parked)!.closed_reason).toMatch(/below the priority floor/);

    // The backlog is a deliverable, so it has to survive into the report.
    expect(finalized(ledger)[0]!.backlog.map((entry) => entry.question)).toEqual([
      "recheck 10.0.0.9 next quarter",
    ]);
  });

  it("ends data_starved rather than completed when a hypothesis was gap-locked", async () => {
    const { ledger, hypothesisIds } = await newLedger();
    await gapLock(ledger, hypothesisIds[0]!);
    expect(ledger.projection.hypotheses.get(hypothesisIds[0]!)!.status).toBe("inconclusive");

    const result = await controllerFor(ledger, [CONCLUDE]).advanceIteration();

    // A hunt that could not see is not a hunt that finished.
    expect(result.hunt_outcome).toBe("data_starved");
    expect(finalized(ledger)[0]!.gaps).toHaveLength(DEFAULT_VERDICTS.gap_lock_threshold);
  });

  it("reads gap-lock off the strength snapshot, not the resolution_reason prose", async () => {
    const { ledger, hypothesisIds } = await newLedger();
    // Says gap-locked, but the numbers say otherwise: the numbers win.
    ledger.patch("hypothesis", hypothesisIds[0]!, {
      status: "inconclusive",
      resolution_reason: "gap-locked: nothing could be seen",
      evidence_strength: {
        corroborating_sources: 1,
        contradicting_records: 0,
        open_gaps: 0,
        attacker_influenceable_only: false,
        survived_disconfirmation: false,
      },
    });

    expect(terminationVerdict(ledger.projection, 1, DEFAULT_TERMINATION, DEFAULT_VERDICTS).outcome).toBe("completed");
  });

  it("keeps completed when something was proven, however blind the rest of the hunt was", async () => {
    const { ledger, hypothesisIds } = await newLedger({ hypotheses: ["h one", "h two"] });
    await gapLock(ledger, hypothesisIds[0]!);
    ledger.patch("hypothesis", hypothesisIds[1]!, { status: "proven", resolution_reason: "survived" });

    expect(terminationVerdict(ledger.projection, 2, DEFAULT_TERMINATION, DEFAULT_VERDICTS).outcome).toBe("completed");
  });

  it("measures the floor against the same score the frontier is ranked by", async () => {
    const { ledger, hypothesisIds } = await newLedger();
    resolve(ledger, hypothesisIds[0]!);
    question(ledger, "fresh thread", { entity_key: "ip:10.0.0.7", spawned_iteration: 1 });

    const [top] = scoredFrontier(ledger.projection, 1);
    expect(top!.score).toBeGreaterThanOrEqual(DEFAULT_TERMINATION.priority_floor);

    expect(terminationVerdict(ledger.projection, 1, DEFAULT_TERMINATION, DEFAULT_VERDICTS).outcome).toBeNull();
    // Same frontier, a floor above every score: now nothing blocks.
    const cleared = terminationVerdict(
      ledger.projection,
      1,
      { ...DEFAULT_TERMINATION, priority_floor: 99 },
      DEFAULT_VERDICTS,
    );
    expect(cleared.outcome).toBe("completed");
  });
});

describe("the budget checkpoint", () => {
  async function parkedHunt(overrides: SpecOverrides = {}) {
    const started = await newLedger({ budgets: CAPPED, ...overrides });
    const result = await controllerFor(started.ledger, [INVESTIGATE]).advanceIteration();
    return { ...started, result };
  }

  it("parks instead of terminating, and refuses to step while parked", async () => {
    const { ledger, result } = await parkedHunt();

    expect(result.hunt_status).toBe("parked");
    expect(ledger.projection.hunt.outcome).toBeNull();
    expect(ledger.projection.hunt.parked_at).not.toBeNull();
    expect(ledger.projection.hunt.parked_reason).toMatch(/budget exhausted/);

    await expect(controllerFor(ledger, [INVESTIGATE]).advanceIteration()).rejects.toThrow(HuntParked);
    await expect(controllerFor(ledger, [INVESTIGATE]).advanceIteration()).rejects.toThrow(
      /extend .*conclude .*abort/s,
    );
  });

  it("concludes rather than parking when the budget runs out on a finished hunt", async () => {
    const { ledger, hypothesisIds } = await newLedger({ budgets: CAPPED });
    resolve(ledger, hypothesisIds[0]!);

    const result = await controllerFor(ledger, [INVESTIGATE]).advanceIteration();

    // Nothing was left to do, so there is nothing to ask an operator about, and
    // budget_terminated would say the hunt stopped short when it did not.
    expect(result.hunt_status).toBe("terminal");
    expect(result.hunt_outcome).toBe("completed");
    expect(ledger.projection.hunt.termination_reason).toMatch(/budget ran out/);
    expect(finalized(ledger)).toHaveLength(1);
  });

  it("takes the outcome from the predicate, not from having run out of money", async () => {
    const { ledger, hypothesisIds } = await newLedger({
      budgets: { max_calls: 2, max_cost_usd: 10, max_wall_ms: 1_800_000 },
    });
    await gapLock(ledger, hypothesisIds[0]!);

    // Blind, not finished — and still not budget_terminated.
    expect((await controllerFor(ledger, [INVESTIGATE]).advanceIteration()).hunt_outcome).toBe("data_starved");
  });

  it("un-parks on an extend that grants headroom", async () => {
    const { ledger, runId } = await parkedHunt();
    steer(runId, "extend", "+3 iterations");

    const result = await controllerFor(ledger, [INVESTIGATE]).advanceIteration();

    expect(ledger.projection.hunt.budgets.max_calls).toBe(4);
    expect(result.iteration).toBe(2);
    expect(result.hunt_status).toBe("active");
  });

  it("clamps an extend to the hard ceiling and says that it clamped", async () => {
    const { ledger, runId } = await parkedHunt({ termination: { hard_max_calls: 3, hard_max_cost_usd: 12 } });
    steer(runId, "extend", "+50 iterations and $500");

    await controllerFor(ledger, [INVESTIGATE]).advanceIteration();

    expect(ledger.projection.hunt.budgets.max_calls).toBe(3);
    expect(ledger.projection.hunt.budgets.max_cost_usd).toBe(12);
    expect(ledger.projection.directives.map((directive) => directive.text).join(" ")).toMatch(
      /clamped to the hard ceiling/,
    );
  });

  it("stays parked when the clamp leaves no room to run", async () => {
    const { ledger, runId } = await parkedHunt({ termination: { hard_max_calls: 1, hard_max_cost_usd: 10 } });
    steer(runId, "extend", "+5 iterations");

    await expect(controllerFor(ledger, [INVESTIGATE]).advanceIteration()).rejects.toThrow(HuntParked);
    expect(ledger.projection.directives.map((directive) => directive.text).join(" ")).toMatch(/stays parked/);
  });

  it("keeps the hunt parked when the grant cannot be read", async () => {
    const { ledger, runId } = await parkedHunt();
    steer(runId, "extend", "give it a bit more room");

    await expect(controllerFor(ledger, [INVESTIGATE]).advanceIteration()).rejects.toThrow(HuntParked);
    expect(ledger.projection.hunt.budgets.max_calls).toBe(1);
    expect(ledger.projection.directives.map((directive) => directive.text).join(" ")).toMatch(/granted nothing/);
  });

  it("ends budget_terminated when the operator accepts the stop", async () => {
    const { ledger, runId, hypothesisIds } = await parkedHunt();
    steer(runId, "conclude", "we are done spending on this");

    // Not completed: the predicate never passed, the money ran out.
    expect((await controllerFor(ledger, []).advanceIteration()).hunt_outcome).toBe("budget_terminated");
    expect(ledger.projection.hypotheses.get(hypothesisIds[0]!)!.status).toBe("inconclusive");
  });

  it("aborts from parked, not just from active", async () => {
    const { ledger, runId } = await parkedHunt();
    steer(runId, "abort", "operator halted the hunt");

    expect((await controllerFor(ledger, []).advanceIteration()).hunt_outcome).toBe("aborted");
  });

  it("expires a hunt parked past the TTL the next time it is touched", async () => {
    const { ledger } = await parkedHunt({ termination: { park_ttl_ms: 86_400_000 } });
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 2 * 86_400_000);

    const result = await controllerFor(ledger, [INVESTIGATE]).advanceIteration();

    // Lazy expiry: no timer ran, the hunt was simply looked at.
    expect(result.hunt_outcome).toBe("aborted");
    expect(ledger.projection.hunt.termination_reason).toMatch(/park TTL/);
  });

  it("leaves a hunt parked inside the TTL alone", async () => {
    const { ledger } = await parkedHunt({ termination: { park_ttl_ms: 86_400_000 } });
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 3_600_000);

    await expect(controllerFor(ledger, [INVESTIGATE]).advanceIteration()).rejects.toThrow(HuntParked);
    expect(ledger.projection.hunt.outcome).toBeNull();
  });
});

describe("outcome precedence and coercion", () => {
  it("never downgrades an outcome already on the record", async () => {
    const { ledger } = await newLedger();
    const controller = controllerFor(ledger, []);

    controller.terminate("data_starved");
    controller.terminate("completed");
    expect(ledger.projection.hunt.outcome).toBe("data_starved");

    // Upward is not a downgrade: an abort discovered later is the truth.
    controller.terminate("aborted");
    expect(ledger.projection.hunt.outcome).toBe("aborted");
    controller.terminate("budget_terminated");
    expect(ledger.projection.hunt.outcome).toBe("aborted");
  });

  it.each(["aborted", "budget_terminated", "data_starved"] as const)(
    "coerces every still-active hypothesis to inconclusive when a hunt ends %s",
    async (outcome) => {
      const { ledger, hypothesisIds } = await newLedger({ hypotheses: ["h one", "h two"] });
      controllerFor(ledger, []).terminate(outcome);

      const hypotheses = hypothesisIds.map((id) => ledger.projection.hypotheses.get(id)!);
      expect(hypotheses.map((hypothesis) => hypothesis.status)).toEqual(["inconclusive", "inconclusive"]);
      // "We stopped looking" is never "we cleared it".
      expect(hypotheses.some((hypothesis) => hypothesis.status === "disproven")).toBe(false);
      expect(hypotheses[0]!.resolution_reason).toMatch(new RegExp(outcome));
    },
  );

  it("leaves a verdict already on the record alone", async () => {
    const { ledger, hypothesisIds } = await newLedger({ hypotheses: ["h one", "h two"] });
    ledger.patch("hypothesis", hypothesisIds[0]!, { status: "proven", resolution_reason: "survived" });

    controllerFor(ledger, []).terminate("aborted");

    expect(ledger.projection.hypotheses.get(hypothesisIds[0]!)!.status).toBe("proven");
    expect(ledger.projection.hypotheses.get(hypothesisIds[1]!)!.status).toBe("inconclusive");
  });
});

describe("Finalize runs on every terminal path", () => {
  const DRIVERS: [string, (ledger: Journal, ids: string[], runId: string) => Promise<void>][] = [
    [
      "completed",
      async (ledger, ids) => {
        resolve(ledger, ids[0]!);
        await controllerFor(ledger, [CONCLUDE]).advanceIteration();
      },
    ],
    [
      "data_starved",
      async (ledger, ids) => {
        await gapLock(ledger, ids[0]!);
        await controllerFor(ledger, [CONCLUDE]).advanceIteration();
      },
    ],
    [
      "budget_terminated",
      async (ledger, _ids, runId) => {
        steer(runId, "conclude", "accepted");
        await controllerFor(ledger, []).advanceIteration();
      },
    ],
    [
      "aborted",
      async (ledger, _ids, runId) => {
        steer(runId, "abort", "halted");
        await controllerFor(ledger, []).advanceIteration();
      },
    ],
  ];

  it.each(DRIVERS)("journals exactly one report when a hunt ends %s", async (outcome, drive) => {
    const started = outcome === "budget_terminated" ? await newLedger({ budgets: CAPPED }) : await newLedger();
    if (outcome === "budget_terminated") {
      await controllerFor(started.ledger, [INVESTIGATE]).advanceIteration();
    }
    await drive(started.ledger, started.hypothesisIds, started.runId);

    expect(started.ledger.projection.hunt.outcome).toBe(outcome);

    const reports = finalized(started.ledger);
    expect(reports).toHaveLength(1);
    expect(reports[0]!.outcome).toBe(outcome);
    expect(renderReport(reports[0]!)).toMatch(new RegExp(`\\*\\*Outcome:\\*\\* ${outcome}`));
  });

  it("finalizes exactly once when a lower-precedence terminate follows", async () => {
    const { ledger } = await newLedger();
    const controller = controllerFor(ledger, []);
    controller.terminate("aborted");
    controller.terminate("completed");
    expect(finalized(ledger)).toHaveLength(1);
  });

  it("rebuilds the same report from the ledger alone", async () => {
    const { ledger, state, runId, hypothesisIds } = await newLedger();
    await gapLock(ledger, hypothesisIds[0]!);
    await controllerFor(ledger, [CONCLUDE]).advanceIteration();
    await ledger.flush();

    // Replay-derived, so it works on any ledger rather than only on the writer's.
    const { Journal } = await import("../../workflows/hunt/journal.js");
    const rebuilt = buildReport((await Journal.open(state, runId)).projection);
    expect(rebuilt).toEqual(finalized(ledger)[0]);
  });

  it("reads as an answer when nothing was proven", async () => {
    const { ledger, hypothesisIds } = await newLedger();
    await gapLock(ledger, hypothesisIds[0]!);
    question(ledger, "was the key used elsewhere?", { entity_key: "aws_key:AKIA1", spawned_iteration: -5 });
    await controllerFor(ledger, [CONCLUDE]).advanceIteration();

    const rendered = renderReport(finalized(ledger)[0]!);
    expect(rendered).toMatch(/could not see well enough/);
    expect(rendered).toMatch(/## Visibility gaps \(3\)/);
    expect(rendered).toMatch(/## Parked backlog/);
    expect(rendered).toMatch(/was the key used elsewhere\?/);
    expect(rendered).toMatch(/Evidence strength at verdict: .* 3 open gap\(s\)/);
  });

  it("reports a parked hypothesis as backlog, not as a verdict", async () => {
    const { ledger, hypothesisIds } = await newLedger();
    resolve(ledger, hypothesisIds[0]!);
    controllerFor(ledger, []).terminate("aborted", "operator halted the hunt");

    const report = finalized(ledger)[0]!;
    expect(report.parked_hypotheses).toHaveLength(1);
    expect(report.reason).toBe("operator halted the hunt");
  });
});

describe("termination is config", () => {
  const specWith = (thresholds: Record<string, number>, budgets?: BudgetLimits) =>
    huntSpec({ ...huntSpecFor(), thresholds, ...(budgets ? { budgets } : {}) });

  it("ships the documented defaults and honours an override", () => {
    expect(specWith({}).termination).toEqual(DEFAULT_TERMINATION);
    expect(specWith({ priority_floor: 9 }).termination).toEqual({
      ...DEFAULT_TERMINATION,
      priority_floor: 9,
    } satisfies Termination);
  });

  it("refuses a ceiling under the budget it is meant to cap", () => {
    expect(() => specWith({ hard_max_calls: 10 }, { max_calls: 30, max_cost_usd: 5, max_wall_ms: 1 })).toThrow(
      /below budgets.max_calls/,
    );
    expect(() => specWith({ priority_floor: 0 })).toThrow(/must be a positive number/);
    expect(() => specWith({ floor: 5 })).toThrow(/unknown thresholds key/);
  });
});
