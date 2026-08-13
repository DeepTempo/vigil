import { copyFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import type { RunJob } from "../../contracts/job.js";
import { InProcessLeases, LEASE_TTL_MS } from "../../core/leases.js";
import { seedFrom } from "../../core/budget.js";
import { InProcessState } from "../../core/state.js";
import { advance, resolveSpec, sweepOnce, type Enqueue } from "../../worker.js";
import { scriptedHarness } from "../support/scripted-harness.js";
import type { ScriptedTurn } from "../support/scripted-provider.js";

const FIXTURES = join(import.meta.dirname, "..", "fixtures");
const RUN = "7d3c2d3e-0000-4000-8000-000000000633";

const CONCLUDE: ScriptedTurn[] = [{ calls: [] }, { emit: { action: "CONCLUDE", rationale: "done", evidence_citations: [] } }];

let config: string;
let state: InProcessState;
let leases: InProcessLeases;
let clock: number;

beforeEach(() => {
  config = join(mkdtempSync(join(tmpdir(), "vigil-watchdog-")), "vigil.config.yaml");
  copyFileSync(join(FIXTURES, "hunt.config.yaml"), config);
  // Anchored to real time, because the park check and the budget pool both read
  // the process clock. A test reaches the past by writing events at a rewound
  // store clock rather than by moving the present.
  clock = Date.now();
  state = new InProcessState(() => clock);
  leases = new InProcessLeases(() => clock);
});

// A ledger the way a first attempt would have left it: the real resolved spec, so
// a resume reads what a resume actually reads, plus whatever else the case needs.
async function opened(
  overrides: Record<string, unknown> | undefined,
  ...rest: readonly Parameters<InProcessState["append"]>[2][number][]
): Promise<void> {
  const spec = await resolveSpec(startJob(overrides));
  await state.append(RUN, 0, [
    {
      run_id: RUN,
      run_kind: "hunt",
      kind: "run",
      payload: { run_kind: "hunt", spec, budgets: spec.budgets, seed: RUN, tenant_id: null, started_by: "test" },
    },
    ...rest,
  ]);
}

function spend(): Parameters<InProcessState["append"]>[2][number] {
  return {
    run_id: RUN,
    run_kind: "hunt",
    kind: "spend",
    payload: { model_id: "m", provider_type: "scripted", role: "lead", tokens: { input: 10, output: 1, cache_read: 0, cache_write: 0 }, cost_usd: null, pricing_source: null },
  };
}

function startJob(overrides?: Record<string, unknown>): Extract<RunJob, { reason: "start" }> {
  return {
    schema_version: 1,
    run_id: RUN,
    run_kind: "hunt",
    tenant_id: null,
    enqueued_at: new Date().toISOString(),
    enqueued_by: "test",
    reason: "start",
    request: { arch: "", playbook: join(FIXTURES, "hunt.playbook.yaml"), config, prompt: "go", ...(overrides ? { overrides } : {}) },
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

function recorder(): Enqueue & { jobs: RunJob[]; ids: string[] } {
  const jobs: RunJob[] = [];
  const ids: string[] = [];
  return {
    jobs,
    ids,
    add: async (_name, job, options) => {
      jobs.push(job);
      ids.push(options.jobId);
    },
  };
}

// The exploit this ticket would otherwise ship. A pool built fresh per resume
// hands a run killed near its ceiling a whole new allowance, and a watchdog that
// resumes it automatically turns that into an unbounded spend loop.
describe("a resumed run continues its budget rather than restarting it", () => {
  // A run killed mid-iteration leaves spend on the ledger and no terminal, which is
  // exactly what the watchdog resumes. Nothing in the new process remembers the
  // first attempt, so the fold is the only thing standing between a killed run and
  // a fresh allowance -- and a watchdog that resumes automatically would otherwise
  // spend the cap again on every crash.
  it("refuses a further call when the ledger's spend fold has reached the cap", async () => {
    await opened({ budgets: { max_calls: 2 } }, spend(), spend());
    expect(await state.terminal(RUN)).toBeNull();

    await advance(state, leases, resumeJob(), scriptedHarness(CONCLUDE));

    // Not one more call: the two on the ledger already spent the allowance.
    expect((await state.read(RUN)).filter((event) => event.kind === "spend")).toHaveLength(2);
    expect((await state.terminal(RUN))?.outcome).toBe("budget_exhausted");
  });

  it("still has its allowance when the fold is short of the cap", async () => {
    await opened({ budgets: { max_calls: 4 } }, spend());

    await advance(state, leases, resumeJob(), scriptedHarness(CONCLUDE));

    expect((await state.read(RUN)).filter((event) => event.kind === "spend").length).toBeGreaterThan(1);
    expect((await state.terminal(RUN))?.outcome).toBe("completed");
  });

  // The pool's wall clock starts at the run event rather than at this process, so
  // a resume does not hand a killed run another half hour.
  it("folds the run's own start time, not the resuming process's", async () => {
    clock -= 120_000;
    await opened(undefined, spend(), spend());
    const started = (await state.read(RUN)).find((event) => event.kind === "run")?.ts;

    const seed = seedFrom(await state.read(RUN));

    expect(seed.spent.calls).toBe(2);
    expect(seed.spent.tokens.input).toBe(20);
    expect(seed.started).toBe(Date.parse(started ?? ""));
  });
});

function checkpoint(id: string): Parameters<InProcessState["append"]>[2][number] {
  return {
    run_id: RUN,
    run_kind: "hunt",
    kind: "checkpoint",
    payload: { checkpoint_id: id, checkpoint_class: "tool_approval", question: "Approve?", raised_at: new Date(clock).toISOString() },
  };
}

function resolution(id: string): Parameters<InProcessState["append"]>[2][number] {
  return {
    run_id: RUN,
    run_kind: "hunt",
    kind: "resolution",
    payload: { checkpoint_id: id, answer: "approve", actor: "someone", text: "go ahead", resolved_at: new Date(clock).toISOString() },
  };
}

const EIGHT_DAYS = 8 * 86_400_000;

describe("a run parked past its TTL is abandoned rather than left parked", () => {
  it("journals a terminal naming how long it actually waited", async () => {
    clock -= EIGHT_DAYS;
    await opened(undefined, checkpoint("apr-unanswered"));
    clock += EIGHT_DAYS;

    await advance(state, leases, resumeJob(), scriptedHarness(CONCLUDE));

    const terminal = await state.terminal(RUN);
    expect(terminal?.outcome).toBe("abandoned");
    expect(terminal?.reason).toBe("parked 8.0 days without an answer");
    // Reaped: a finished run is nobody's work, so nothing sweeps it again.
    clock += LEASE_TTL_MS + 1;
    expect(await leases.sweep(LEASE_TTL_MS, 10)).toEqual([]);
  });

  // The clock only runs while the answer is outstanding, so a checkpoint raised
  // long ago and answered is not a park at all.
  it("leaves a run alone when its checkpoint was answered", async () => {
    clock -= EIGHT_DAYS;
    await opened(undefined, checkpoint("apr-answered"), resolution("apr-answered"));
    clock += EIGHT_DAYS;

    await advance(state, leases, resumeJob(), scriptedHarness(CONCLUDE));

    expect((await state.terminal(RUN))?.outcome).not.toBe("abandoned");
  });

  it("leaves a run alone inside its TTL", async () => {
    clock -= 86_400_000;
    await opened(undefined, checkpoint("apr-unanswered"));
    clock += 86_400_000;

    await advance(state, leases, resumeJob(), scriptedHarness(CONCLUDE));

    expect((await state.terminal(RUN))?.outcome).not.toBe("abandoned");
  });
});

describe("a run nobody is working on is put back on the queue", () => {
  it("enqueues a resume for a lapsed claim and not for a held one", async () => {
    await leases.claim(RUN, "hunt", "worker-a", LEASE_TTL_MS);

    const queue = recorder();
    expect(await sweepOnce(leases, queue)).toBe(0);

    clock += LEASE_TTL_MS + 1;
    expect(await sweepOnce(leases, queue)).toBe(1);
    expect(queue.jobs[0]?.reason).toBe("resume");
    expect(queue.jobs[0]?.run_id).toBe(RUN);
    expect(queue.jobs[0]?.enqueued_by).toBe("watchdog");
  });

  // Claiming is part of discovering, so the run is not handed out twice in the
  // same interval however many sweepers are looking.
  it("hands a due run to exactly one sweeper", async () => {
    await leases.claim(RUN, "hunt", "worker-a", LEASE_TTL_MS);
    clock += LEASE_TTL_MS + 1;

    const [first, second] = [recorder(), recorder()];
    const counts = await Promise.all([sweepOnce(leases, first), sweepOnce(leases, second)]);

    expect(counts.filter((count) => count === 1)).toHaveLength(1);
    expect([...first.ids, ...second.ids]).toHaveLength(1);
  });

  // A parked run's ledger position never moves, so an id derived from it would
  // repeat and the queue would drop every check after the first.
  it("gives each resume its own job id", async () => {
    await leases.claim(RUN, "hunt", "worker-a", LEASE_TTL_MS);
    const queue = recorder();

    clock += LEASE_TTL_MS + 1;
    await sweepOnce(leases, queue);
    clock += LEASE_TTL_MS + 1;
    await sweepOnce(leases, queue);

    expect(queue.ids).toHaveLength(2);
    expect(queue.ids[0]).not.toBe(queue.ids[1]);
  });

  // The join the other tests in this file leave out, and the one that matters: a
  // sweep that enqueues is worth nothing unless the worker on the far side of the
  // queue can take the run. A sweeper that stamped its own name on the row would
  // be refused by its own reservation here, and every resume would be a no-op --
  // the exact bug the watchdog exists to fix, reintroduced by the watchdog.
  it("drives the run when the worker picks the queued resume up", async () => {
    await opened(undefined);
    await leases.claim(RUN, "hunt", "dead-worker", LEASE_TTL_MS);
    clock += LEASE_TTL_MS + 1;

    const queue = recorder();
    expect(await sweepOnce(leases, queue)).toBe(1);
    await advance(state, leases, queue.jobs[0] as RunJob, scriptedHarness(CONCLUDE));

    expect((await state.terminal(RUN))?.outcome).toBe("completed");
  });

  // A run that failed before it opened a ledger cannot be resumed and cannot
  // journal a terminal, so a row left behind for it is swept forever and throws
  // every time. Nothing else would ever drop it.
  it("leaves no lease behind for a start that never opened a ledger", async () => {
    const missing = { ...startJob(), request: { arch: "", playbook: "/nowhere.yaml", config: "/nowhere.yaml", prompt: "go" } };
    await expect(advance(state, leases, missing, scriptedHarness([]))).rejects.toThrow();

    clock += LEASE_TTL_MS + 1;
    expect(await sweepOnce(leases, recorder())).toBe(0);
  });
});

// max_wall_ms is a ceiling on work, and waiting for a person is not work. If the
// pool's clock ran while a run was parked, the two ceilings would contradict each
// other -- a seven-day park TTL behind a thirty-minute wall budget -- and every
// checkpoint answered late would resume straight into wall_exhausted.
describe("a run does not spend wall time while it is parked", () => {
  it("still has its allowance when the answer comes long after it parked", async () => {
    clock -= 2 * 3_600_000;
    await opened(undefined, checkpoint("apr-late"));
    clock += 2 * 3_600_000;
    await state.append(RUN, (await state.latestSeq(RUN) ?? -1) + 1, [resolution("apr-late")]);

    await advance(state, leases, resumeJob(), scriptedHarness(CONCLUDE));

    expect((await state.terminal(RUN))?.outcome).toBe("completed");
  });

  // Only waiting is excused. A worker that died and was reclaimed spent the hours
  // it spent, which is what stops a crash loop buying a fresh clock every time.
  it("counts the time a run was running but nobody was asked anything", async () => {
    clock -= 2 * 3_600_000;
    await opened(undefined, spend());
    clock += 2 * 3_600_000;

    await advance(state, leases, resumeJob(), scriptedHarness(CONCLUDE));

    expect((await state.terminal(RUN))?.outcome).toBe("budget_exhausted");
  });
});

describe("two workers cannot hold one run", () => {
  it("refuses the second claim while the first is live", async () => {
    expect(await leases.claim(RUN, "hunt", "worker-a", LEASE_TTL_MS)).toBe(true);
    expect(await leases.claim(RUN, "hunt", "worker-b", LEASE_TTL_MS)).toBe(false);
  });

  // Losing the claim is how a worker learns it has been declared dead: it stops
  // rather than paying for a call the ledger will refuse to take.
  it("tells the displaced holder its renewal failed", async () => {
    await leases.claim(RUN, "hunt", "worker-a", LEASE_TTL_MS);
    clock += LEASE_TTL_MS + 1;
    await leases.claim(RUN, "hunt", "worker-b", LEASE_TTL_MS);

    expect(await leases.renew(RUN, "worker-a", LEASE_TTL_MS)).toBe(false);
    expect(await leases.renew(RUN, "worker-b", LEASE_TTL_MS)).toBe(true);
  });

  // A worker that cannot claim returns rather than throwing: someone else driving
  // the run is the good case, and a throw would fill the failed set with non-events.
  it("returns quietly when another worker holds the run", async () => {
    await leases.claim(RUN, "hunt", "worker-a", LEASE_TTL_MS);
    await advance(state, leases, startJob(), scriptedHarness(CONCLUDE));

    expect(await state.latestSeq(RUN)).toBeNull();
  });
});
