import { drain, streamTurn } from "../../core/stream.js";
import type { Harness } from "../../core/loop.js";
import type { RoleSpec, RunSpec } from "../../core/spec.js";
import { SpecError } from "../../core/spec.js";
import { renderDigest } from "./render.js";
import type { HuntKinds } from "./ledger.js";
import type { DecisionProvider, DisconfirmationCritic, WorkerDispatcher } from "./ports.js";
import type {
  Decision,
  DecisionResult,
  Digest,
  DispatchRequest,
  DispatchResult,
  NullCheckInput,
  NullCheckResult,
  WorkerEvidence,
} from "./types.js";

// The hunt's four ports over the harness. The controller decides; these only
// carry a question to a model and an answer back, and never touch the ledger.
export interface AdapterOptions {
  harness: Harness<HuntKinds>;
  spec: RunSpec;
  run_id: string;
  actions: readonly string[];
  signal?: AbortSignal;
}

function role(spec: RunSpec, name: "lead" | "critic"): RoleSpec {
  const held = spec.roles[name];
  if (held === undefined) throw new SpecError(`arch ${spec.arch} declares no ${name}, which the hunt requires`);
  return held;
}

function turnFor(options: AdapterOptions, id: string, spec: RoleSpec, task: string) {
  const { runtime } = options.spec;
  return {
    run_id: options.run_id,
    run_kind: "hunt" as const,
    role: id,
    system: spec.prompt,
    task,
    schema: spec.output_schema,
    max_turns: runtime.max_turns,
    approvals: new Set(options.spec.approvals),
    verbs: options.actions,
    result_cap: runtime.result_cap,
    recall_limit: runtime.recall_limit,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  };
}

// What a turn cost, from what the harness journaled rather than a second tally:
// the pool is the authority on money and this is reading it, not keeping books.
function spentOn(harness: Harness<HuntKinds>, before: number): number {
  return Math.max(0, harness.budget.spent.cost_usd - before);
}

// One digest in, one decision out. The digest is rendered rather than handed
// over as an object, because what the lead reasons about is what it can read.
export function decisionProvider(options: AdapterOptions): DecisionProvider {
  const lead = role(options.spec, "lead");

  return {
    decide: async (digest: Digest): Promise<DecisionResult> => {
      const before = options.harness.budget.spent.cost_usd;
      const outcome = await drain(
        streamTurn<Decision, HuntKinds>(turnFor(options, "lead", lead, renderDigest(digest)), options.harness),
      );
      if (outcome.value === null) throw new SpecError(`the lead emitted no decision: ${outcome.reason}`);

      return {
        decision: outcome.value,
        model_id: options.harness.provider.model,
        prompt_version: options.spec.arch,
        cost_usd: spentOn(options.harness, before),
        ...(outcome.rejected.length === 0 ? {} : { rejected_attempts: outcome.rejected }),
      };
    },
  };
}

interface WorkerAnswer {
  results?: unknown[];
  ips_to_check?: string[];
}

// A worker's emission, as evidence records. Anything the schema did not require
// is dropped rather than guessed at: the controller stamps identity and time.
function evidenceFrom(answer: WorkerAnswer): WorkerEvidence[] {
  if (!Array.isArray(answer.results)) return [];
  return answer.results.map((row) => {
    const record = row as Record<string, unknown>;
    return {
      source_system: String(record["source_system"] ?? ""),
      summary: String(record["summary"] ?? ""),
      salience: (record["salience"] ?? "routine") as WorkerEvidence["salience"],
      why_notable: String(record["why_notable"] ?? ""),
      payload: (record["payload"] ?? {}) as Record<string, unknown>,
      ...(Array.isArray(record["supports"]) ? { supports: record["supports"] as string[] } : {}),
      ...(Array.isArray(record["weakens"]) ? { weakens: record["weakens"] as string[] } : {}),
      ...(typeof record["attacker_influenceable"] === "boolean"
        ? { attacker_influenceable: record["attacker_influenceable"] }
        : {}),
    } as WorkerEvidence;
  });
}

// A failure is a result, not a throw: a worker that burned tokens and then died
// still spent them, and the controller records the gap either way.
export function workerDispatcher(options: AdapterOptions): WorkerDispatcher {
  return {
    dispatch: async (request: DispatchRequest): Promise<DispatchResult> => {
      const worker = options.spec.roles.workers[request.agent_id];
      if (worker === undefined) {
        return {
          dispatch_id: request.dispatch_id,
          evidence: [],
          failed: true,
          failure_reason: `no worker ${request.agent_id} in this arch`,
          cost_usd: 0,
        };
      }

      const before = options.harness.budget.spent.cost_usd;
      // The dispatch's own signal wins where it has one: an operator halting the
      // hunt mid-query is a narrower stop than the run losing its lease.
      const scoped = { ...options, ...(request.signal === undefined ? {} : { signal: request.signal }) };
      const task = [request.query_intent, request.focus && `Focus: ${request.focus}`].filter((part) => part).join("\n\n");
      const outcome = await drain(
        streamTurn<WorkerAnswer, HuntKinds>(turnFor(scoped, request.agent_id, worker, task), options.harness),
      );

      const cost_usd = spentOn(options.harness, before);
      if (outcome.value === null) {
        return { dispatch_id: request.dispatch_id, evidence: [], failed: true, failure_reason: outcome.reason, cost_usd };
      }
      const questions = Array.isArray(outcome.value.ips_to_check) ? outcome.value.ips_to_check : [];
      return {
        dispatch_id: request.dispatch_id,
        evidence: evidenceFrom(outcome.value),
        ...(questions.length === 0 ? {} : { questions }),
        failed: false,
        failure_reason: "",
        cost_usd,
      };
    },
  };
}

interface CriticAnswer {
  benign_explanation?: string;
  benign_explanation_stands?: boolean;
  rationale?: string;
}

// The critic argues the benign case against the raw evidence. Its answer is
// inverted here: the hypothesis survives exactly when the benign case does not.
export function disconfirmationCritic(options: AdapterOptions): DisconfirmationCritic {
  const critic = role(options.spec, "critic");

  return {
    argueNull: async (check: NullCheckInput): Promise<NullCheckResult> => {
      const before = options.harness.budget.spent.cost_usd;
      const task = [
        `Hypothesis: ${check.statement}`,
        check.narrative,
        `Evidence:\n${JSON.stringify(check.evidence, null, 2)}`,
      ]
        .filter((part) => part)
        .join("\n\n");
      const outcome = await drain(
        streamTurn<CriticAnswer, HuntKinds>(turnFor(options, "critic", critic, task), options.harness),
      );

      const cost_usd = spentOn(options.harness, before);
      // A critic that could not answer leaves the hypothesis standing rather than
      // proving it: an unargued null is not a null that failed.
      if (outcome.value === null) {
        return {
          survives: true,
          strongest_benign_explanation: "",
          rationale: `the critic did not answer: ${outcome.reason}`,
          cost_usd,
          model_id: options.harness.provider.model,
          prompt_version: options.spec.arch,
        };
      }

      return {
        survives: outcome.value.benign_explanation_stands !== true,
        strongest_benign_explanation: String(outcome.value.benign_explanation ?? ""),
        rationale: String(outcome.value.rationale ?? ""),
        cost_usd,
        model_id: options.harness.provider.model,
        prompt_version: options.spec.arch,
      };
    },
  };
}
