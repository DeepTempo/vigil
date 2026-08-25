import { describe, expect, it } from "vitest";
import { announceOpen, httpAnnounce, noAnnounce } from "../../core/checkpoints.js";
import { InProcessState } from "../../core/state.js";
import type { CheckpointPayload, NewEvent } from "../../contracts/events.js";

const RUN = "7f1c2d3e-0000-4000-8000-000000000634";

function raised(checkpoint_id: string, checkpoint_class = "tool_approval"): NewEvent<Record<never, never>> {
  const payload: CheckpointPayload = {
    checkpoint_id,
    checkpoint_class,
    question: "Approve isolating the host?",
    raised_at: new Date().toISOString(),
  };
  return { run_id: RUN, run_kind: "hunt", kind: "checkpoint", payload };
}

describe("telling a human a run has parked", () => {
  // The gap this closes: a run parked, the ledger recorded it, and nothing put the
  // question anywhere a person would look. Only the compose path did.
  it("sends the checkpoint the ledger recorded, not a second description of it", async () => {
    const state = new InProcessState();
    await state.append(RUN, [raised("apr-abc123")]);
    const sent: Array<Record<string, unknown>> = [];

    await announceOpen(
      state,
      RUN,
      "hunt",
      "apr-abc123",
      async (runId, runKind, payload) => void sent.push({ runId, runKind, ...payload }),
    );

    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({
      runId: RUN,
      runKind: "hunt",
      checkpoint_id: "apr-abc123",
      checkpoint_class: "tool_approval",
      question: "Approve isolating the host?",
    });
  });

  it("says nothing about a checkpoint the ledger does not hold", async () => {
    const state = new InProcessState();
    let called = false;
    await announceOpen(state, RUN, "hunt", "apr-missing", async () => void (called = true));
    expect(called).toBe(false);
  });

  it("carries the class through, so a workflow's own checkpoints are told apart", async () => {
    const state = new InProcessState();
    await state.append(RUN, [raised("chk-1", "verdict_review")]);
    const classes: string[] = [];
    await announceOpen(state, RUN, "hunt", "chk-1", async (_run, _kind, payload) => {
      classes.push(payload.checkpoint_class);
    });
    expect(classes).toEqual(["verdict_review"]);
  });
});

describe("the announce port over HTTP", () => {
  const payload: CheckpointPayload = {
    checkpoint_id: "apr-abc123",
    checkpoint_class: "tool_approval",
    question: "Approve?",
    raised_at: "2026-08-13T00:00:00.000Z",
  };

  it("posts to the run's own checkpoints path with the shared secret", async () => {
    const seen: Array<{ url: string; init: RequestInit }> = [];
    const announce = httpAnnounce({
      url: "http://backend:6987/internal/runs",
      token: "s3cret",
      fetch: async (url, init) => {
        seen.push({ url: String(url), init: init as RequestInit });
        return new Response(null, { status: 204 });
      },
    });

    await announce(RUN, "hunt", payload);

    expect(seen[0]?.url).toBe(`http://backend:6987/internal/runs/${RUN}/checkpoints`);
    expect((seen[0]?.init.headers as Record<string, string>)["authorization"]).toBe("Bearer s3cret");
    expect(JSON.parse(String(seen[0]?.init.body))).toMatchObject({ checkpoint_id: "apr-abc123", run_kind: "hunt" });
  });

  // Telling someone is not the run. A backend that cannot take the notice must not
  // fail a run that has already parked and recorded why.
  it("does not throw when the endpoint is unreachable", async () => {
    const announce = httpAnnounce({
      url: "http://backend:6987/internal/runs",
      token: "s3cret",
      fetch: async () => {
        throw new Error("connection refused");
      },
    });
    await expect(announce(RUN, "hunt", payload)).resolves.toBeUndefined();
  });

  it("does nothing at all when no destination is configured", async () => {
    await expect(noAnnounce(RUN, "hunt", payload)).resolves.toBeUndefined();
  });
});
