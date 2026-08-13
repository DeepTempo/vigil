import { afterAll, beforeEach, describe, expect, it } from "vitest";
import pg from "pg";
import { randomUUID } from "node:crypto";
import { LedgerRepository } from "../../ledger/repository.js";
import type { NewEvent, RunKind } from "../../contracts/events.js";

const pool = new pg.Pool({
  connectionString: process.env["DATABASE_URL"] ?? "postgres://vigil:vigil@localhost:55432/vigil_test",
});
const ledger = new LedgerRepository(pool);

afterAll(() => pool.end());

let runId: string;
beforeEach(() => {
  runId = randomUUID();
});

function runEvent(id: string): NewEvent<Record<never, never>> {
  return {
    run_id: id,
    run_kind: "hunt",
    kind: "run",
    payload: {
      run_kind: "hunt",
      spec: { arch: "arch/threathunt.yaml" },
      budgets: { max_calls: 0, max_cost_usd: 0, max_wall_ms: 600_000, max_park_ms: 604_800_000 },
      seed: id,
      tenant_id: null,
      started_by: "test",
    },
  };
}

function terminalEvent(id: string): NewEvent<Record<never, never>> {
  return {
    run_id: id,
    run_kind: "hunt",
    kind: "terminal",
    payload: { outcome: "completed", reason: "done" },
  };
}

describe("the ledger is append-only and derives nothing", () => {
  it("assigns seq itself and reads events back in order", async () => {
    const next = await ledger.append(runId, [runEvent(runId), terminalEvent(runId)]);
    expect(next).toBe(2);

    const events = await ledger.read(runId);
    expect(events.map((event) => [event.seq, event.kind])).toEqual([
      [0, "run"],
      [1, "terminal"],
    ]);
    expect(await ledger.latestSeq(runId)).toBe(1);
    expect(await ledger.terminal(runId)).toEqual({ outcome: "completed", reason: "done" });
  });

  it("reports an unknown run as absent rather than empty", async () => {
    expect(await ledger.latestSeq(randomUUID())).toBeNull();
    expect(await ledger.terminal(randomUUID())).toBeNull();
  });

  it("leaves nothing behind when a batch fails partway", async () => {
    await ledger.append(runId, [runEvent(runId)]);
    const bad = { ...terminalEvent(runId), run_kind: null as unknown as RunKind };
    await expect(ledger.append(runId, [terminalEvent(runId), bad])).rejects.toThrow();

    expect(await ledger.read(runId)).toHaveLength(1);
  });
});

// Positions come from the store, so a caller cannot get concurrency wrong. What the
// composite key still guarantees is that no position is issued twice.
describe("concurrent writers each take their own position", () => {
  it("gives two writers racing on one run distinct positions", async () => {
    await ledger.append(runId, [runEvent(runId)]);

    await Promise.all([
      ledger.append(runId, [terminalEvent(runId)]),
      ledger.append(runId, [terminalEvent(runId)]),
    ]);

    expect((await ledger.read(runId)).map((event) => event.seq)).toEqual([0, 1, 2]);
  });

  it("holds under a wider race, with the table still holding one row per seq", async () => {
    await ledger.append(runId, [runEvent(runId)]);

    await Promise.all(Array.from({ length: 8 }, () => ledger.append(runId, [terminalEvent(runId)])));

    const { rows } = await pool.query<{ seqs: string; rows: string }>(
      "SELECT count(DISTINCT seq) AS seqs, count(*) AS rows FROM agent_events WHERE run_id = $1",
      [runId],
    );
    expect(rows[0]).toEqual({ seqs: "9", rows: "9" });
  });
});
