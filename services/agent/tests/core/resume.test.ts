import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import type { RunJob } from "../../contracts/job.js";
import { InProcessState } from "../../core/state.js";
import { advance, resolveSpec, specOf } from "../../worker.js";
import { scriptedHarness } from "../support/scripted-harness.js";
import type { ScriptedTurn } from "../support/scripted-provider.js";

const CONCLUDE: ScriptedTurn[] = [{ calls: [] }, { emit: { action: "CONCLUDE", rationale: "done", evidence_citations: [] } }];

const FIXTURES = join(import.meta.dirname, "..", "fixtures");
const RUN = "7d3c2d3e-0000-4000-8000-000000000619";

let config: string;
beforeEach(() => {
  config = join(mkdtempSync(join(tmpdir(), "vigil-resume-")), "vigil.config.yaml");
  copyFileSync(join(FIXTURES, "hunt.config.yaml"), config);
});

// The registry resolves the arch, so the request names only the two layers an
// operator supplies per run.
function startJob(run_kind: RunJob["run_kind"] = "hunt", overrides?: Record<string, unknown>): Extract<RunJob, { reason: "start" }> {
  const tighten = overrides === undefined ? {} : { overrides };
  return {
    schema_version: 1,
    run_id: RUN,
    run_kind,
    tenant_id: null,
    enqueued_at: new Date().toISOString(),
    enqueued_by: "test",
    reason: "start",
    request: { arch: "", playbook: join(FIXTURES, "hunt.playbook.yaml"), config, prompt: "go", ...tighten },
  };
}

function resumeJob(): RunJob {
  return {
    schema_version: 1,
    run_id: RUN,
    run_kind: "hunt",
    tenant_id: null,
    enqueued_at: new Date().toISOString(),
    enqueued_by: "watchdog",
    reason: "resume",
  };
}

function rewriteBudget(iterations: number): void {
  writeFileSync(config, readFileSync(config, "utf8").replace("max_calls: 12", `max_calls: ${iterations}`), "utf8");
}

describe("resolving a run", () => {
  it("routes the run kind through the registry to its arch file", async () => {
    expect((await resolveSpec(startJob())).arch).toBe("threathunt");
  });

  // Startup, not runtime: the kind is resolved before the ledger opens.
  it("refuses a run kind no arch is registered for", async () => {
    await expect(resolveSpec(startJob("tally"))).rejects.toThrow(/no architecture is registered for run_kind tally/);
  });

  it("lets an explicit arch path override the registry's default", async () => {
    const job = startJob();
    job.request.arch = join(import.meta.dirname, "..", "..", "arch", "threathunt.yaml");
    expect((await resolveSpec(job)).dispatch.max_workers).toBe(4);
  });
});

describe("the arch a run started under is journaled", () => {
  it("writes the resolved spec into the run event", async () => {
    const state = new InProcessState();
    await advance(state, startJob(), scriptedHarness(CONCLUDE));

    const opened = await specOf(state, RUN);
    expect(opened?.arch).toBe("threathunt");
    expect(opened?.budgets).toEqual({ max_calls: 12, max_cost_usd: 5, max_wall_ms: 1_800_000 });
  });

  // The whole point of journaling it: the file moved, the run did not.
  it("keeps a resumed run on the spec it opened with after the config is edited", async () => {
    const state = new InProcessState();
    await advance(state, startJob(), scriptedHarness(CONCLUDE));

    rewriteBudget(99);
    expect((await resolveSpec(startJob())).budgets.max_calls).toBe(99);

    await advance(state, resumeJob(), scriptedHarness(CONCLUDE));
    expect((await specOf(state, RUN))?.budgets.max_calls).toBe(12);
  });

  it("refuses to resume a run that has no ledger", async () => {
    await expect(advance(new InProcessState(), resumeJob(), scriptedHarness(CONCLUDE))).rejects.toThrow(/has no ledger/);
  });
});

describe("what the caller enqueuing a run may tighten", () => {
  it("lowers a ceiling the config set", async () => {
    const spec = await resolveSpec(startJob("hunt", { budgets: { max_cost_usd: 0.5 } }));
    expect(spec.budgets.max_cost_usd).toBe(0.5);
  });

  it("leaves the ceilings it did not name", async () => {
    const plain = await resolveSpec(startJob());
    const tightened = await resolveSpec(startJob("hunt", { budgets: { max_cost_usd: 0.5 } }));
    expect(tightened.budgets.max_calls).toBe(plain.budgets.max_calls);
  });

  it("refuses a ceiling of zero, which is a run that cannot start rather than one that cannot overspend", async () => {
    await expect(resolveSpec(startJob("hunt", { budgets: { max_cost_usd: 0 } }))).rejects.toThrow(/must be a positive number/);
  });

  it("refuses an unknown budget key rather than accepting a knob nothing reads", async () => {
    await expect(resolveSpec(startJob("hunt", { budgets: { max_dollars: 5 } }))).rejects.toThrow(/unknown overrides.budgets key/);
  });

  it("refuses to override anything but budgets and runtime", async () => {
    // The deployment's ceilings are the deployment's; the arch is not negotiable.
    await expect(resolveSpec(startJob("hunt", { roles: {} }))).rejects.toThrow(/may name budgets or runtime/);
  });
});
