import { describe, expect, it } from "vitest";
import { archFor } from "../../arch/registry.js";
import type { AgentEvent } from "../../contracts/events.js";
import { AUTO_ACTOR, raiseCheckpoint, resolveCheckpoint } from "../../workflows/hunt/checkpoints.js";
import { huntProjection } from "../../workflows/hunt/projection.js";
import { evidenceOn, newLedger, type Started } from "../support/hunt.js";

async function project(started: Started) {
  await started.ledger.flush();
  return huntProjection(started.runId, await started.state.read(started.runId));
}

// A hunt has no steps to report progress against, so a reader outside this process
// is told what it has tested and how each belief stands.
describe("what a reader is told about a hunt in flight", () => {
  it("names every hypothesis and where it stands", async () => {
    const started = await newLedger();
    const view = await project(started);

    expect(view.hypotheses.map((one) => one.hypothesis_id)).toEqual(started.hypothesisIds);
    expect(view.hypotheses.every((one) => one.statement.trim() !== "")).toBe(true);
    expect(view.status).toBe("active");
  });

  it("counts the evidence the run has gathered", async () => {
    const started = await newLedger();
    evidenceOn(started.ledger, started.hypothesisIds[0] as string);
    evidenceOn(started.ledger, started.hypothesisIds[0] as string);

    expect((await project(started)).evidence_count).toBe(2);
  });

  // The only question a supervisor actually asks of a parked run. Reported from
  // the ledger rather than a flag, so a checkpoint already answered is not re-asked.
  it("reports the checkpoint a resolution has to answer", async () => {
    const started = await newLedger();
    const raised = raiseCheckpoint("scope_extension", 1, "widen to the DMZ?");
    started.ledger.append({ kind: "checkpoint", payload: raised });
    const view = await project(started);

    expect(view.open_checkpoint?.checkpoint_class).toBe("scope_extension");
    expect(view.open_checkpoint?.question).toBe("widen to the DMZ?");
  });

  it("reports nothing open once the checkpoint is answered", async () => {
    const started = await newLedger();
    const raised = raiseCheckpoint("scope_extension", 1, "widen?");
    started.ledger.append({ kind: "checkpoint", payload: raised });
    started.ledger.append({ kind: "resolution", payload: resolveCheckpoint(raised, "approve", AUTO_ACTOR, "yes") });

    expect((await project(started)).open_checkpoint).toBeNull();
  });
});

// The registry entry is what serve.ts reads: a hunt whose projection is unregistered
// answers 404 no matter how well the fold works.
it("is what the hunt's arch entry hands a reader", async () => {
  const started = await newLedger();
  await started.ledger.flush();
  const events = await started.state.read(started.runId);
  // Erased the way serve.ts hands them over: it reads an untyped ledger and the
  // entry is what knows the kind.
  const erased = events as unknown as readonly AgentEvent<Record<never, never>>[];

  expect(archFor("hunt").projection?.(started.runId, erased)).toEqual(huntProjection(started.runId, events));
});
