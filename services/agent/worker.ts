import { Queue, Worker } from "bullmq";
import { hostname } from "node:os";
import { randomUUID } from "node:crypto";
import pg from "pg";
import { archFor } from "./arch/registry.js";
import { httpAnswers, journalAnswers, noAnswers, type Answers } from "./core/answers.js";
import { harnessFor, internalToken, type HarnessFactory } from "./harness.js";
import { chatPort, chatServer } from "./serve.js";
import { jobIdFor, RUN_QUEUE, JOB_SCHEMA_VERSION, type RunJob } from "./contracts/job.js";
import type { AgentEvent, CheckpointPayload, ResolutionPayload, RunKind, RunPayload } from "./contracts/events.js";
import {
  LEASE_TTL_MS,
  PARK_EVERY_MS,
  RENEW_EVERY_MS,
  SWEEP_EVERY_MS,
  type Leases,
} from "./core/leases.js";
import { LeaseRepository } from "./ledger/leases.js";
import { seedFrom } from "./core/budget.js";
import type { State } from "./core/seams.js";
import { httpPlaybooks, isReference, type PlaybookResolver } from "./core/playbooks.js";
import { assembleSpec, buildSpec, DEFAULT_BUDGETS, loadArch, parseConfig, parsePlaybook, SpecError, withOverrides, type RunSpec } from "./core/spec.js";
import { LedgerRepository } from "./ledger/repository.js";
import { httpMirror, nullMirror, type Mirror } from "./workflows/compose/mirror.js";
import { runCompose } from "./workflows/compose/workflow.js";
import type { ComposeKinds } from "./workflows/compose/vocabulary.js";
import { runLead, type LeadKinds } from "./workflows/lead/workflow.js";

type StartJob = Extract<RunJob, { reason: "start" }>;

// The registry is the only resolver, and it runs before the ledger opens: an
// unregistered run kind fails at startup rather than seven iterations in.
export async function resolveSpec(job: StartJob, resolve: PlaybookResolver = defaultResolver()): Promise<RunSpec> {
  const entry = archFor(job.run_kind);
  const arch = job.request.arch === "" ? entry.arch : job.request.arch;
  const tighten = (spec: RunSpec): RunSpec => withOverrides(spec, job.request.overrides);
  if (!isReference(job.request.playbook)) {
    return tighten(buildSpec({ arch, playbook: job.request.playbook, config: job.request.config }, entry.actions, entry.owned, job.request.prompt));
  }

  // A reference answers with both layers, so a config path beside one is a second
  // source for a layer that already has one rather than an override of it.
  if (job.request.config !== "") {
    throw new SpecError(`${job.request.playbook} resolves its own config, so ${job.request.config} has nothing to say`);
  }
  const layers = await resolve(job.request.playbook);
  return tighten(
    assembleSpec({
      arch: loadArch(arch, entry.actions),
      playbook: parsePlaybook(layers.playbook, entry.owned),
      config: parseConfig(layers.config, entry.owned),
      prompt: job.request.prompt,
    }),
  );
}

// Off unless a deployment says where to mirror to: a run whose progress nobody
// collects still runs, and the ledger is the record either way.
function mirrorFor(): Mirror {
  const url = process.env["VIGIL_RUNS_URL"];
  return url === undefined || url === "" ? nullMirror : httpMirror({ url, token: internalToken() });
}

// The same endpoint the compose mirror answers from, read-only. Off unless a
// deployment says where, so a run nobody can answer parks rather than proceeds.
function answersFor(): Answers {
  const url = process.env["VIGIL_RUNS_URL"];
  return url === undefined || url === "" ? noAnswers : httpAnswers({ url, token: internalToken() });
}

function defaultResolver(): PlaybookResolver {
  return httpPlaybooks({
    url: process.env["VIGIL_PLAYBOOKS_URL"] ?? "http://localhost:6987/internal/playbooks",
    token: internalToken(),
  });
}

// The spec a run started under, read off the ledger. A resume re-reads no file,
// so an edited arch or config cannot reach a run already in flight.
//
// Budgets are backfilled from the defaults for keys the journaled spec predates.
// A run in flight when a new ceiling ships has never heard of it, and the arithmetic
// downstream is not defensive: Math.min against an undefined limit is NaN, which
// reaches Postgres as an interval it refuses, and the run then fails every sweep
// forever. Backfilling also keeps the promise above intact -- what a resume must not
// do is re-read the *file*, not decline to know a default.
export async function specOf(state: State, runId: string): Promise<RunSpec | null> {
  const opened = (await state.read(runId)).find((event) => event.kind === "run");
  if (opened === undefined) return null;
  const spec = (opened.payload as RunPayload).spec as RunSpec;
  return { ...spec, budgets: { ...DEFAULT_BUDGETS, ...spec.budgets } };
}

// A workflow's event kinds are its own and the repository is generic over them, so
// the ledger is retyped per branch rather than every workflow sharing one union.
function as<K extends Record<string, unknown>>(state: State): State<K> {
  return state as unknown as State<K>;
}

// The one place a run kind becomes a loop. A kind with no workflow throws here,
// before the ledger opens, rather than journalling a run nothing will ever advance.
async function drive(
  state: State,
  job: RunJob,
  spec: RunSpec,
  build: HarnessFactory,
  signal: AbortSignal,
): Promise<void> {
  const { run_kind: kind, run_id, enqueued_by: started_by } = job;
  // Folded off the ledger, so a resumed run continues its allowance instead of
  // starting one. Without this, a run killed near its ceiling comes back with a
  // full budget, and a watchdog that resumes it automatically makes that a loop.
  const seed = seedFrom(await state.read(run_id));

  if (kind === "compose") {
    await runCompose(build(kind, spec, as<ComposeKinds>(state), undefined, seed), { run_id, spec, started_by, mirror: mirrorFor() });
    return;
  }
  if (kind === "hunt" || kind === "investigate") {
    const entry = archFor(kind);
    const harness = build(kind, spec, as<LeadKinds>(state), undefined, seed);
    await runLead(harness, { run_id, run_kind: kind, spec, actions: entry.actions, halts: entry.halts, started_by, answers: answersFor(), signal });
    return;
  }
  throw new SpecError(`no workflow is wired for run_kind ${kind}`);
}

// Resolves the spec on a start and reads it back off the ledger on a resume, so an
// edited arch never reaches a run in flight, then hands both to the workflow.
//
// The lease is taken here and given back here, and renewed by a timer rather than
// by the workflow: an iteration can sit on one model call for minutes, so renewal
// cannot hang off an iteration boundary. Losing it aborts the call in flight,
// because a worker that has been declared dead is paying for a response no one
// will record.
export async function advance(
  state: State,
  leases: Leases,
  job: RunJob,
  build: HarnessFactory = harnessFor,
): Promise<void> {
  if ((await state.terminal(job.run_id)) !== null) {
    await leases.finish(job.run_id);
    return;
  }

  const owner = workerName();
  if (!(await leases.claim(job.run_id, job.run_kind, owner, LEASE_TTL_MS))) return;

  const halt = new AbortController();
  const renewing = setInterval(() => {
    void leases.renew(job.run_id, owner, LEASE_TTL_MS).then(
      (held) => {
        if (!held) halt.abort(new Error(LOST_LEASE));
      },
      // A renewal that could not be read is not a lost lease: the claim outlives
      // several attempts, and killing the run over one failed query would be worse
      // than the late renewal it is recovering from.
      () => {},
    );
  }, RENEW_EVERY_MS);

  try {
    const latest = await state.latestSeq(job.run_id);
    if (latest === null && job.reason !== "start") throw new Error(`cannot resume ${job.run_id}: it has no ledger`);

    const spec = latest === null ? await resolveSpec(job as StartJob) : await specOf(state, job.run_id);
    if (spec === null) throw new Error(`cannot advance ${job.run_id}: its ledger holds no run event`);

    // Before the park check, not after it: abandoning is irreversible, and a run
    // whose answer is sitting at the endpoint unjournaled has been answered. The
    // workflow journals again on every iteration; this is idempotent against what
    // the ledger already holds, so the second call appends nothing.
    await journalAnswers(state, job.run_id, job.run_kind, answersFor());

    if (await abandonIfParkedOut(state, leases, job, spec)) return;
    await drive(state, job, spec, build, halt.signal);
    await settle(state, leases, job, spec, owner);
  } catch (error) {
    await abandon(job, error);
    await forget(state, leases, job.run_id);
    throw error;
  } finally {
    clearInterval(renewing);
  }
}

// A run that failed before it opened a ledger is not a run: no terminal can be
// journaled for it and no resume can read it back, so its lease row would sit there
// being swept forever, throwing on every attempt. Dropped here because this is the
// only place that knows the ledger stayed empty.
//
// A failure with a ledger behind it keeps its row: that run is real and unfinished,
// and the sweeper reclaiming it is exactly right.
async function forget(state: State, leases: Leases, runId: string): Promise<void> {
  if ((await state.latestSeq(runId)) === null) await leases.finish(runId);
}

export const LOST_LEASE = "the lease was reclaimed by another worker";

// Which process, not which person: a directive's actor is who steered a run and
// this is what is holding it. Reported to the console, never read to decide.
function workerName(): string {
  return `${hostname()}:${process.pid}`;
}

// Whether this worker is still the run's business, once the workflow returns. A
// run that reached terminal is nobody's; one that parked stays on the list and is
// looked at again when its interval passes or the console pulls it forward.
async function settle(state: State, leases: Leases, job: RunJob, spec: RunSpec, owner: string): Promise<void> {
  if ((await state.terminal(job.run_id)) !== null) {
    await reap(leases, job.run_id);
    return;
  }
  await leases.release(job.run_id, owner, Math.min(PARK_EVERY_MS, spec.budgets.max_park_ms));
}

// A run that dies before it journals a terminal leaves its record open, and a
// resolution failure dies before there is a ledger to journal one onto.
async function abandon(job: RunJob, error: unknown): Promise<void> {
  if (job.run_kind !== "compose") return;
  await mirrorFor().terminal(job.run_id, "failed", error instanceof Error ? error.message : String(error), "");
}

// A checkpoint nobody answered for max_park_ms. Saying so beats leaving the run
// parked forever, and abandoned is not aborted: aborted means a human stopped the
// run, and this is the case where nobody decided anything at all.
async function abandonIfParkedOut(state: State, leases: Leases, job: RunJob, spec: RunSpec): Promise<boolean> {
  const events = await state.read(job.run_id);
  const waited = parkedFor(events);
  if (waited === null || waited < spec.budgets.max_park_ms) return false;

  const days = (waited / 86_400_000).toFixed(1);
  const from = ((await state.latestSeq(job.run_id)) ?? -1) + 1;
  await state.append(job.run_id, from, [
    {
      run_id: job.run_id,
      run_kind: job.run_kind,
      kind: "terminal",
      payload: { outcome: "abandoned", reason: `parked ${days} days without an answer` },
    },
  ]);
  await reap(leases, job.run_id);
  return true;
}

// How long the oldest unanswered checkpoint has been waiting, or null when none
// is. Read off the ledger's own timestamps, which is the one thing in this ticket
// that folds ts -- and the reason only the store may stamp it.
function parkedFor(events: readonly AgentEvent<Record<never, never>>[]): number | null {
  const answered = new Set(
    events.filter((one) => one.kind === "resolution").map((one) => (one.payload as ResolutionPayload).checkpoint_id),
  );
  const open = events.filter(
    (one) => one.kind === "checkpoint" && !answered.has((one.payload as CheckpointPayload).checkpoint_id),
  );
  const raised = open.map((one) => Date.parse(one.ts)).filter((at) => Number.isFinite(at));
  return raised.length === 0 ? null : Date.now() - Math.min(...raised);
}

// What a finished run leaves behind, which is less than the word suggests. Remote
// dispatch is request and response with a timeout, so no far side holds work of
// ours; dispatch events are journaled after their outcome rather than before it;
// and the approval mirror ADR 0003 describes is not written by this layer yet. So
// the lease row is the only thing to drop.
//
// Not the run's queued directives. Deleting them would take away the record of an
// instruction that never reached the run, which #634 is supposed to surface, and
// journaling them first would mean appending after a terminal -- a property worth
// less than the tidiness. agent_directives has no retention and neither does
// agent_events: one reaper for both is its own job, as the ADR already says.
async function reap(leases: Leases, runId: string): Promise<void> {
  await leases.finish(runId);
}

function connectionUrl(): string {
  const url = process.env["DATABASE_URL"];
  if (url === undefined || url === "") throw new Error("DATABASE_URL is not set");
  return url;
}

function redisUrl(): URL {
  return new URL(process.env["REDIS_URL"] ?? "redis://localhost:6379/0");
}

// A run whose claim has lapsed, put back on the queue. Two cases reach here and
// neither needs telling apart: a worker died holding the run, or a parked run's
// interval passed. Both mean "look at this again", and advance() reads the ledger
// to decide which it is.
//
// Nothing distinguishes a sweep from a start to the queue either, so the resume
// carries no request -- the ledger holds the spec, and the RunJob union makes a
// resume that read one fail to compile.
// Structurally what the sweeper needs of a queue, so it is drivable without a
// Redis. BullMQ's Queue satisfies it as it stands.
export interface Enqueue {
  add(name: string, job: RunJob, options: { jobId: string }): Promise<unknown>;
}

// The reservation lasts a lease TTL because that is the order of magnitude a job
// spends between being queued and being picked up. It is not ownership: the row
// keeps a null owner, so the worker that dequeues the job can claim it, and if no
// worker ever does the run is offered again once the reservation lapses.
export async function sweepOnce(leases: Leases, queue: Enqueue, limit = 50): Promise<number> {
  const due = await leases.sweep(LEASE_TTL_MS, limit);
  for (const claim of due) {
    const job: RunJob = {
      schema_version: JOB_SCHEMA_VERSION,
      run_id: claim.run_id,
      run_kind: claim.run_kind,
      tenant_id: null,
      enqueued_at: new Date().toISOString(),
      enqueued_by: "watchdog",
      reason: "resume",
    };
    await queue.add(RUN_QUEUE, job, { jobId: jobIdFor(job, randomUUID()) });
  }
  return due.length;
}

export interface Running {
  worker: Worker<RunJob>;
  ledger: LedgerRepository;
  leases: LeaseRepository;
  close: () => Promise<void>;
}

// The queue drains durable runs and the HTTP surface serves chat, which is
// synchronous and would gain nothing from a queue hop but latency. One process,
// one pool, two ways in.
export function startWorker(): Running {
  const pool = new pg.Pool({ connectionString: connectionUrl() });
  const ledger = new LedgerRepository(pool);
  const leases = new LeaseRepository(pool);
  const url = redisUrl();
  const connection = {
    host: url.hostname,
    port: Number(url.port || 6379),
    db: Number(url.pathname.slice(1) || 0),
    ...(url.password === "" ? {} : { password: url.password }),
  };

  // Long, because the lease is the liveness signal and a second clock that
  // disagreed with it would either double-process a run or wedge one. BullMQ's
  // stalled sweep still retires a dead worker's job eventually, and the lease
  // refuses it if it comes back around.
  const worker = new Worker<RunJob>(RUN_QUEUE, (job) => advance(ledger, leases, job.data), {
    connection,
    lockDuration: LEASE_TTL_MS * 10,
  });

  // A plain interval rather than a repeatable job: a repeat key lives in Redis and
  // can be lost on a deploy, and a watchdog that has silently stopped looks exactly
  // like one with nothing to do. This cannot stop while the process lives.
  //
  // Several replicas all sweep. That is harmless rather than merely tolerable --
  // the claim is one conditional UPDATE, so only the sweeper that wins a row
  // enqueues it.
  const producer = new Queue<RunJob>(RUN_QUEUE, { connection });
  const sweeping = setInterval(() => {
    void sweepOnce(leases, producer).catch(() => {
      // A sweep that could not read the table tries again next tick. Throwing here
      // would take the process down with every run on it.
    });
  }, SWEEP_EVERY_MS);

  return { worker, ledger, leases, close: async () => {
    clearInterval(sweeping);
    await worker.close();
    await producer.close();
    await pool.end();
  } };
}

if (process.argv[1] !== undefined && import.meta.url.endsWith(process.argv[1].split("/").pop() ?? "")) {
  const running = startWorker();
  const serving = chatServer(running.ledger).listen(chatPort());
  const stop = () => {
    serving.close();
    void running.close();
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
