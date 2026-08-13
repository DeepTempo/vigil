import { afterAll, beforeEach, describe, expect, it } from "vitest";
import pg from "pg";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { LedgerRepository } from "../../ledger/repository.js";
import { LeaseRepository } from "../../ledger/leases.js";
import { advance } from "../../worker.js";
import { InProcessDirectiveQueue } from "../../workflows/hunt/directives.js";
import type { RunJob } from "../../contracts/job.js";
import { isLead, respondingProvider } from "../support/responding-provider.js";
import { budgetOf, FRESH, unmeteredQuota } from "../../core/budget.js";
import { localDispatch } from "../../core/dispatch.js";
import { nullMemory } from "../../core/memory.js";
import { registryOf } from "../../core/registry.js";
import type { HarnessFactory } from "../../harness.js";

// A hunt started through the queue must reach the hunt loop. Routing it to the
// generic one produced a run that completed and looked fine, and hunted nothing.
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

function startJob(id: string): RunJob {
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

// Answers by role rather than position: one iteration asks the lead, the workers
// and the critic, which a positional script cannot keep up with.
function huntHarness(): HarnessFactory {
  const provider = respondingProvider({
    emit: (schema) =>
      isLead(schema)
        ? { action: "CONCLUDE", rationale: "nothing to pursue", evidence_citations: [] }
        : { results: [] },
    ticks: 0,
  });
  return (_kind, spec, state, memory = nullMemory, seed = FRESH) => ({
    provider,
    registry: registryOf([], {}),
    dispatch: localDispatch,
    budget: budgetOf(spec.budgets, unmeteredQuota, Date.now, seed),
    memory,
    state,
  });
}

async function run(id: string, build: HarnessFactory = huntHarness()): Promise<void> {
  await advance(ledger, leases, startJob(id), build, new InProcessDirectiveQueue());
}

describe("a hunt started through the queue", () => {
  it("opens a ledger carrying the hunt's own state, not a generic run", async () => {
    await run(runId);

    const [first] = await ledger.read(runId);
    expect(first?.kind).toBe("run");
    // Both halves: the contract's spec, which resume reads, and the hunt state
    // its projection folds. A run event with only one of them breaks the other.
    expect(first?.payload).toMatchObject({
      spec: { arch: "threathunt" },
      started_by: "test",
      hunt: { name: expect.any(String), status: expect.any(String) },
    });
  });

  it("journals the hunt's vocabulary rather than the lead loop's", async () => {
    await run(runId);

    const kinds = new Set((await ledger.read(runId)).map((event) => String(event.kind)));
    // finalize is the hunt's report and nothing else writes one, so it is what
    // tells a hunt apart from a run the generic lead loop drove to the same end.
    expect(kinds.has("finalize")).toBe(true);
    // And the run is over for everyone, not only for the hunt's own projection:
    // the lease, the API's status and the sweeper all read the domain-free kind.
    expect(kinds.has("terminal")).toBe(true);
  });

  it("reaches a terminal the ledger can report", async () => {
    await run(runId);

    const terminal = await ledger.terminal(runId);
    expect(terminal).not.toBeNull();
    expect((await ledger.read(runId)).at(-1)?.kind).toBe("terminal");
  });

  // The run event is written once. A second attempt on a settled run must not
  // re-open it -- an empty script proves nothing reached the model at all.
  it("does not re-open a hunt that already reached terminal", async () => {
    await run(runId);
    const settled = (await ledger.read(runId)).length;

    const refusing: HarnessFactory = () => {
      throw new Error("a settled run must not reach a workflow at all");
    };
    await advance(ledger, leases, startJob(runId), refusing, new InProcessDirectiveQueue());

    expect(await ledger.read(runId)).toHaveLength(settled);
  });
});
