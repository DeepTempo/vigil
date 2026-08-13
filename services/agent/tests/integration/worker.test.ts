import { afterAll, beforeEach, describe, expect, it } from "vitest";
import pg from "pg";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { LedgerRepository } from "../../ledger/repository.js";
import { LeaseRepository } from "../../ledger/leases.js";
import { advance, resolveSpec } from "../../worker.js";
import type { RunJob } from "../../contracts/job.js";
import type { ScriptedTurn } from "../support/scripted-provider.js";
import { scriptedHarness } from "../support/scripted-harness.js";

const FIXTURES = join(import.meta.dirname, "..", "fixtures");

const pool = new pg.Pool({
  connectionString: process.env["DATABASE_URL"] ?? "postgres://vigil:vigil@localhost:55432/vigil_test",
});
const ledger = new LedgerRepository(pool);
const leases = new LeaseRepository(pool);

afterAll(() => pool.end());

let runId: string;
beforeEach(() => {
  runId = randomUUID();
});

type StartJob = Extract<RunJob, { reason: "start" }>;

function startJob(id: string): StartJob {
  return {
    schema_version: 1,
    run_id: id,
    run_kind: "hunt",
    tenant_id: null,
    enqueued_at: new Date().toISOString(),
    enqueued_by: "test",
    reason: "start",
    request: {
      arch: "",
      playbook: join(FIXTURES, "hunt.playbook.yaml"),
      config: join(FIXTURES, "hunt.config.yaml"),
      prompt: "go",
    },
  };
}

// Built rather than spread from a start job: a resume carries no request, and a
// fixture that smuggled one in would not be testing the contract.
function resumeJob(id: string): RunJob {
  return {
    schema_version: 1,
    run_id: id,
    run_kind: "hunt",
    tenant_id: null,
    enqueued_at: new Date().toISOString(),
    enqueued_by: "watchdog",
    reason: "resume",
  };
}

const CONCLUDE: ScriptedTurn[] = [{ calls: [] }, { emit: { action: "CONCLUDE", rationale: "nothing to pursue", evidence_citations: [] } }];

describe("a run reaches its workflow", () => {
  it("opens the ledger and drives the workflow to terminal", async () => {
    await advance(ledger, leases, startJob(runId), scriptedHarness(CONCLUDE));

    const events = await ledger.read(runId);
    expect(events.at(0)?.kind).toBe("run");
    expect(events.at(-1)?.kind).toBe("terminal");
    expect(await ledger.terminal(runId)).toMatchObject({ outcome: "completed" });
  });

  it("journals the resolved spec into the run event, so a resume needs no other state", async () => {
    await advance(ledger, leases, startJob(runId), scriptedHarness(CONCLUDE));

    const [first] = await ledger.read(runId);
    expect(first?.kind).toBe("run");
    expect(first?.payload).toMatchObject({ spec: { arch: "threathunt" }, started_by: "test" });
  });

  // A crash between the two appends must resume rather than collide on seq 0.
  it("is re-entrant against a ledger that already opened", async () => {
    const job = startJob(runId);
    await ledger.append(runId, 0, [
      {
        run_id: runId,
        run_kind: "hunt",
        kind: "run",
        payload: {
          run_kind: "hunt",
          spec: await resolveSpec(job),
          budgets: { max_calls: 0, max_cost_usd: 0, max_wall_ms: 600_000, max_park_ms: 604_800_000 },
          seed: runId,
          tenant_id: null,
          started_by: "crashed-worker",
        },
      },
    ]);

    await advance(ledger, leases, resumeJob(runId), scriptedHarness(CONCLUDE));

    const events = await ledger.read(runId);
    expect(events.at(0)?.kind).toBe("run");
    expect(events.at(-1)?.kind).toBe("terminal");
  });

  it("is idempotent when the run already reached terminal", async () => {
    await advance(ledger, leases, startJob(runId), scriptedHarness(CONCLUDE));
    const settled = (await ledger.read(runId)).length;

    // The second call must not reach the workflow at all: the script would run out.
    await advance(ledger, leases, resumeJob(runId), scriptedHarness([]));

    expect(await ledger.read(runId)).toHaveLength(settled);
  });

  it("refuses to resume a run that has no ledger", async () => {
    await expect(advance(ledger, leases, resumeJob(runId), scriptedHarness(CONCLUDE))).rejects.toThrow(/has no ledger/);
  });
});
