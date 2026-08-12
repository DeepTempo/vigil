import { Worker } from "bullmq";
import pg from "pg";
import { archFor } from "./arch/registry.js";
import { harnessFor, internalToken, type HarnessFactory } from "./harness.js";
import { chatPort, chatServer } from "./serve.js";
import { RUN_QUEUE, type RunJob } from "./contracts/job.js";
import type { RunKind, RunPayload } from "./contracts/events.js";
import type { State } from "./core/seams.js";
import { httpPlaybooks, isReference, type PlaybookResolver } from "./core/playbooks.js";
import { assembleSpec, buildSpec, loadArch, parseConfig, parsePlaybook, SpecError, type RunSpec } from "./core/spec.js";
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
  if (!isReference(job.request.playbook)) {
    return buildSpec({ arch, playbook: job.request.playbook, config: job.request.config }, entry.actions, entry.owned, job.request.prompt);
  }

  // A reference answers with both layers, so a config path beside one is a second
  // source for a layer that already has one rather than an override of it.
  if (job.request.config !== "") {
    throw new SpecError(`${job.request.playbook} resolves its own config, so ${job.request.config} has nothing to say`);
  }
  const layers = await resolve(job.request.playbook);
  return assembleSpec({
    arch: loadArch(arch, entry.actions),
    playbook: parsePlaybook(layers.playbook, entry.owned),
    config: parseConfig(layers.config, entry.owned),
    prompt: job.request.prompt,
  });
}

// Off unless a deployment says where to mirror to: a run whose progress nobody
// collects still runs, and the ledger is the record either way.
function mirrorFor(): Mirror {
  const url = process.env["VIGIL_RUNS_URL"];
  return url === undefined || url === "" ? nullMirror : httpMirror({ url, token: internalToken() });
}

function defaultResolver(): PlaybookResolver {
  return httpPlaybooks({
    url: process.env["VIGIL_PLAYBOOKS_URL"] ?? "http://localhost:6987/internal/playbooks",
    token: internalToken(),
  });
}

// The spec a run started under, read off the ledger. A resume re-reads no file,
// so an edited arch or config cannot reach a run already in flight.
export async function specOf(state: State, runId: string): Promise<RunSpec | null> {
  const opened = (await state.read(runId)).find((event) => event.kind === "run");
  return opened === undefined ? null : ((opened.payload as RunPayload).spec as RunSpec);
}

// A workflow's event kinds are its own and the repository is generic over them, so
// the ledger is retyped per branch rather than every workflow sharing one union.
function as<K extends Record<string, unknown>>(state: State): State<K> {
  return state as unknown as State<K>;
}

// The one place a run kind becomes a loop. A kind with no workflow throws here,
// before the ledger opens, rather than journalling a run nothing will ever advance.
async function drive(state: State, job: RunJob, spec: RunSpec, build: HarnessFactory): Promise<void> {
  const { run_kind: kind, run_id, enqueued_by: started_by } = job;

  if (kind === "compose") {
    await runCompose(build(kind, spec, as<ComposeKinds>(state)), { run_id, spec, started_by, mirror: mirrorFor() });
    return;
  }
  if (kind === "hunt" || kind === "investigate") {
    const entry = archFor(kind);
    const harness = build(kind, spec, as<LeadKinds>(state));
    await runLead(harness, { run_id, run_kind: kind, spec, actions: entry.actions, halts: entry.halts, started_by });
    return;
  }
  throw new SpecError(`no workflow is wired for run_kind ${kind}`);
}

// Resolves the spec on a start and reads it back off the ledger on a resume, so an
// edited arch never reaches a run in flight, then hands both to the workflow.
export async function advance(state: State, job: RunJob, build: HarnessFactory = harnessFor): Promise<void> {
  if ((await state.terminal(job.run_id)) !== null) return;

  try {
    const latest = await state.latestSeq(job.run_id);
    if (latest === null && job.reason !== "start") throw new Error(`cannot resume ${job.run_id}: it has no ledger`);

    const spec = latest === null ? await resolveSpec(job as StartJob) : await specOf(state, job.run_id);
    if (spec === null) throw new Error(`cannot advance ${job.run_id}: its ledger holds no run event`);

    await drive(state, job, spec, build);
  } catch (error) {
    await abandon(job, error);
    throw error;
  }
}

// A run that dies before it journals a terminal leaves its record open, and a
// resolution failure dies before there is a ledger to journal one onto.
async function abandon(job: RunJob, error: unknown): Promise<void> {
  if (job.run_kind !== "compose") return;
  await mirrorFor().terminal(job.run_id, "failed", error instanceof Error ? error.message : String(error), "");
}

function connectionUrl(): string {
  const url = process.env["DATABASE_URL"];
  if (url === undefined || url === "") throw new Error("DATABASE_URL is not set");
  return url;
}

function redisUrl(): URL {
  return new URL(process.env["REDIS_URL"] ?? "redis://localhost:6379/0");
}

export interface Running {
  worker: Worker<RunJob>;
  ledger: LedgerRepository;
  close: () => Promise<void>;
}

// The queue drains durable runs and the HTTP surface serves chat, which is
// synchronous and would gain nothing from a queue hop but latency. One process,
// one pool, two ways in.
export function startWorker(): Running {
  const pool = new pg.Pool({ connectionString: connectionUrl() });
  const ledger = new LedgerRepository(pool);
  const url = redisUrl();
  const worker = new Worker<RunJob>(RUN_QUEUE, (job) => advance(ledger, job.data), {
    connection: {
      host: url.hostname,
      port: Number(url.port || 6379),
      db: Number(url.pathname.slice(1) || 0),
      ...(url.password === "" ? {} : { password: url.password }),
    },
  });
  return { worker, ledger, close: async () => {
    await worker.close();
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
