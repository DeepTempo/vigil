import { createHash } from "node:crypto";
import Ajv, { type ValidateFunction } from "ajv";
import { ZERO_TOKENS, type Refusal, type Reservation, type TokenCounts } from "../contracts/budget.js";
import type { CheckpointPayload, NewEvent, ResolutionPayload, RunKind } from "../contracts/events.js";
import type { RegisteredTool, ToolResult } from "../contracts/tool.js";
import type { PricingBudget } from "./budget.js";
import { estimateTokens } from "./limiter.js";
import { ProviderError, type Message, type Provider, type ToolSchema, type Turn, type TurnRequest } from "./provider.js";
import type { Registry } from "./registry.js";
import { scannerFor, wrap, type Wrapped } from "./security.js";
import type { Memory, State, ToolDispatch } from "./seams.js";

// A checkpoint a gated call raised, so a run parked on approval can be found by
// class alone. Workflow classes are the workflow's; this one is the harness's.
export const TOOL_APPROVAL = "tool_approval";

const OUTPUT_ESTIMATE = 1_024;

export type Status = "completed" | "waiting_approval" | "failed";

// Everything the loop is given rather than builds. Provider and registry sit
// beside the four seams because they are injected on the same terms.
export interface Harness<Kinds extends Record<string, unknown> = Record<never, never>> {
  provider: Provider;
  registry: Registry;
  dispatch: ToolDispatch;
  budget: PricingBudget;
  memory: Memory;
  state: State<Kinds>;
}

export interface TurnConfig {
  run_id: string;
  run_kind: RunKind;
  role: string;
  system: string;
  task: string;
  schema: Record<string, unknown>;
  // The harness's own cap on tool turns, held whatever a workflow asks for.
  max_turns: number;
  // Which tools ask a human first. Deployment's answer rather than a property of
  // the tool: #589's tool contract is settled and carries no such field, and
  // which checkpoints ask a human belongs to the config layer (CONTEXT.md).
  approvals: ReadonlySet<string>;
  // The workflow's vocabulary, for the injection scanner and nothing else. The
  // harness passes it to the scanner and never reads it.
  verbs: readonly string[];
  result_cap: number;
  recall_limit: number;
  signal?: AbortSignal;
}

export interface Attempt {
  tool: string;
  args: string;
  wrapped: Wrapped;
}

export interface Outcome<T> {
  status: Status;
  value: T | null;
  refusal: Refusal | null;
  // Set only when parked: the call the harness stopped at, and the checkpoint a
  // resolution must answer for it to go through.
  pending: { checkpoint_id: string; tool: string; args: string } | null;
  // True when the tool loop was stopped by the cap rather than by the model, so
  // a workflow knows the answer was reached over a truncated set of calls.
  capped: boolean;
  transcript: Message[];
  calls: Attempt[];
  turns: number;
  rejected: string[];
  // The harness's own events for this turn. A workflow appends them with its own
  // so one iteration is one transaction; commitTurn does exactly that.
  events: NewEvent<Record<never, never>>[];
  from: number;
  reason: string;
}

// Harness events first, then the workflow's, in one append: a spend precedes
// whatever the workflow concluded from it, and a partly written iteration never
// lands (services/agent/ledger/repository.ts).
export async function commitTurn<Kinds extends Record<string, unknown>>(
  state: State<Kinds>,
  runId: string,
  outcome: Pick<Outcome<unknown>, "events" | "from">,
  own: readonly NewEvent<Kinds>[],
): Promise<number> {
  // The domain-free kinds are in every workflow's ledger by construction
  // (ADR-0005), but Omit does not distribute over a union, so the two NewEvent
  // types do not overlap structurally and the compiler cannot see it.
  const harness = outcome.events as readonly unknown[] as readonly NewEvent<Kinds>[];
  return state.append(runId, outcome.from, [...harness, ...own]);
}

export async function runTurn<T>(cfg: TurnConfig, harness: Harness): Promise<Outcome<T>> {
  const run = new Run<T>(cfg, harness);
  return run.execute();
}

class Run<T> {
  private readonly scan: ReturnType<typeof scannerFor>;
  private readonly tools: readonly RegisteredTool[];
  private readonly events: NewEvent<Record<never, never>>[] = [];
  private readonly calls: Attempt[] = [];
  private readonly rejected: string[] = [];
  private readonly transcript: Message[] = [];
  private from = 0;
  private turns = 0;
  private capped = false;

  constructor(
    private readonly cfg: TurnConfig,
    private readonly harness: Harness,
  ) {
    this.scan = scannerFor(cfg.verbs);
    this.tools = harness.registry.granted(cfg.role);
  }

  async execute(): Promise<Outcome<T>> {
    this.from = ((await this.harness.state.latestSeq(this.cfg.run_id)) ?? -1) + 1;
    const answered = await resolutionsOf(this.harness.state, this.cfg.run_id);

    // Recalled once and rendered into the opening turn, never re-recalled per
    // tool turn: a prefix that changes mid-loop is a prefix that cannot cache.
    const recalled = await this.harness.memory.recall(this.cfg.task, this.cfg.recall_limit);
    this.transcript.push({ role: "system", content: this.cfg.system });
    this.transcript.push({ role: "user", content: opening(this.cfg.task, recalled) });

    const parked = await this.toolLoop(answered);
    if (parked !== null) return parked;
    return this.emit();
  }

  // Returns an outcome only when the run parks; otherwise the loop ends because
  // the model stopped asking for tools or because the cap stopped it.
  private async toolLoop(answered: ReadonlyMap<string, ResolutionPayload["answer"]>): Promise<Outcome<T> | null> {
    const schemas = this.tools.map(schemaOf);
    while (this.turns < this.cfg.max_turns) {
      const turn = await this.burn({ messages: this.transcript, tools: schemas });
      if ("refusal" in turn) return this.failed(turn.refusal, "the budget refused a call inside the tool loop");
      this.turns += 1;
      if (turn.tool_calls.length === 0) return null;

      this.transcript.push({ role: "assistant", content: turn.content, tool_calls: turn.tool_calls });
      for (const call of turn.tool_calls) {
        const tool = this.tools.find((granted) => granted.id === call.tool);
        if (tool === undefined) {
          this.record(call.tool, call.args, refused(`${call.tool} is not granted to ${this.cfg.role}`), call.id);
          continue;
        }
        const gate = this.gate(tool, call.args, answered);
        if (gate.kind === "park") return this.park(gate.checkpoint_id, tool.id, call.args);
        if (gate.kind === "rejected") {
          this.record(tool.id, call.args, refused("a reviewer rejected this call"), call.id);
          continue;
        }
        this.record(tool.id, call.args, await this.invoke(tool, call.args), call.id);
      }
    }

    // The cap stops the tool loop, not the run: a role that gathered something
    // still answers over what it gathered, and says the set was truncated.
    this.capped = true;
    return null;
  }

  private gate(
    tool: RegisteredTool,
    args: string,
    answered: ReadonlyMap<string, ResolutionPayload["answer"]>,
  ): { kind: "allowed" } | { kind: "rejected" } | { kind: "park"; checkpoint_id: string } {
    if (!this.cfg.approvals.has(tool.id)) return { kind: "allowed" };
    // Derived from the call rather than generated, so a resumed run recognises
    // the resolution that answered this exact call and no other.
    const checkpoint_id = approvalId(this.cfg.run_id, tool.id, args);
    const answer = answered.get(checkpoint_id);
    if (answer === undefined) return { kind: "park", checkpoint_id };
    return answer === "approve" ? { kind: "allowed" } : { kind: "rejected" };
  }

  private async invoke(tool: RegisteredTool, rawArgs: string): Promise<ToolResult> {
    const args = parseArgs(rawArgs);
    if (args === null) return { ok: false, failure: { kind: "invalid_args", detail: "arguments were not valid JSON" } };
    return this.harness.dispatch.invoke(tool, args);
  }

  // Every result goes through wrap, so nothing reaches the transcript unscanned
  // whatever the dispatch implementation handed back.
  private record(tool: string, args: string, result: ToolResult, callId: string): void {
    const wrapped = wrap(tool, result, this.scan, this.cfg.result_cap);
    this.calls.push({ tool, args, wrapped });
    this.transcript.push({ role: "tool", call_id: callId, content: wrapped.text });
  }

  private async emit(): Promise<Outcome<T>> {
    const validate = compile(this.cfg.schema);
    const ask: Message = { role: "user", content: "Emit your answer now as JSON matching the schema." };
    const messages: Message[] = [...this.transcript, ask];

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const turn = await this.burn({ messages, tools: [], emit: this.cfg.schema });
      if ("refusal" in turn) return this.failed(turn.refusal, "the budget refused the emission");

      const parsed = tryParse(turn.content);
      if (parsed !== undefined && validate(parsed)) {
        return this.done("completed", parsed as T, "the role answered");
      }

      const reason = parsed === undefined ? "the response was not valid JSON" : errorsOf(validate);
      this.rejected.push(`${reason}: ${turn.content.slice(0, 400)}`);
      // The rejected emission goes back as the assistant turn it was. Without it
      // the model is asked to correct something it cannot see, and the re-ask
      // lands as a second consecutive user turn.
      messages.push({ role: "assistant", content: turn.content, tool_calls: [] });
      messages.push({ role: "user", content: `That emission was rejected -- ${reason}. Emit a valid answer.` });
    }

    return this.done("failed", null, `the role never emitted a valid answer: ${this.rejected.join(" | ")}`);
  }

  // One model call with the budget around it: reserved before, committed after,
  // and committed rather than released when the call fails, because tokens it
  // burned before failing were still spent.
  private async burn(request: Omit<TurnRequest, "signal">): Promise<Turn | { refusal: Refusal }> {
    const model = this.harness.provider.model;
    const estimate = { ...ZERO_TOKENS, input: estimateTokens(JSON.stringify(request.messages)), output: OUTPUT_ESTIMATE };
    const outcome = this.harness.budget.reserve(model, estimate);
    if (!outcome.ok) return { refusal: outcome.refusal };

    try {
      const turn = await this.harness.provider.turn({ ...request, ...(this.cfg.signal ? { signal: this.cfg.signal } : {}) });
      this.settle(turn.tokens, outcome.reservation);
      return turn;
    } catch (error) {
      this.settle(error instanceof ProviderError ? error.tokens : ZERO_TOKENS, outcome.reservation);
      throw error;
    }
  }

  private settle(tokens: TokenCounts, reservation: Reservation): void {
    const payload = this.harness.budget.price(this.harness.provider.model, this.cfg.role, tokens, reservation);
    if (payload === null) {
      this.harness.budget.release(reservation);
      return;
    }
    this.harness.budget.commit(reservation, payload);
    this.events.push({ run_id: this.cfg.run_id, run_kind: this.cfg.run_kind, kind: "spend", payload });
  }

  private park(checkpoint_id: string, tool: string, args: string): Outcome<T> {
    const payload: CheckpointPayload = {
      checkpoint_id,
      checkpoint_class: TOOL_APPROVAL,
      question: `${this.cfg.role} wants to call ${tool} with ${args}. Approve?`,
      raised_at: new Date().toISOString(),
    };
    this.events.push({ run_id: this.cfg.run_id, run_kind: this.cfg.run_kind, kind: "checkpoint", payload });
    const outcome = this.done("waiting_approval", null, `parked on approval for ${tool}`);
    return { ...outcome, pending: { checkpoint_id, tool, args } };
  }

  private failed(refusal: Refusal, reason: string): Outcome<T> {
    return { ...this.done("failed", null, reason), refusal };
  }

  private done(status: Status, value: T | null, reason: string): Outcome<T> {
    return {
      status,
      value,
      refusal: null,
      pending: null,
      capped: this.capped,
      transcript: this.transcript,
      calls: this.calls,
      turns: this.turns,
      rejected: this.rejected,
      events: this.events,
      from: this.from,
      reason,
    };
  }
}

// Only an approving or rejecting resolution counts; a checkpoint with none is
// still open, which is what keeps the run parked (ADR-0003).
async function resolutionsOf(
  state: State,
  runId: string,
): Promise<ReadonlyMap<string, ResolutionPayload["answer"]>> {
  const events = await state.read(runId);
  const answered = new Map<string, ResolutionPayload["answer"]>();
  for (const event of events) {
    if (event.kind !== "resolution") continue;
    const payload = event.payload as ResolutionPayload;
    answered.set(payload.checkpoint_id, payload.answer);
  }
  return answered;
}

export function approvalId(runId: string, tool: string, args: string): string {
  return `apr-${createHash("sha256").update(`${runId}\n${tool}\n${args}`).digest("hex").slice(0, 12)}`;
}

function opening(task: string, recalled: readonly string[]): string {
  if (recalled.length === 0) return task;
  return `${task}\n\nRecalled from earlier work:\n${recalled.map((note) => `- ${note}`).join("\n")}`;
}

function schemaOf(tool: RegisteredTool): ToolSchema {
  return { id: tool.id, description: tool.description, parameters: tool.parameters };
}

function refused(detail: string): ToolResult {
  return { ok: false, failure: { kind: "refused", detail } };
}

function parseArgs(raw: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(raw === "" ? "{}" : raw);
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function tryParse(content: string): unknown {
  try {
    return JSON.parse(content);
  } catch {
    return undefined;
  }
}

const ajv = new Ajv({ allErrors: true, strict: false });
const compiled = new Map<string, ValidateFunction>();

function compile(schema: Record<string, unknown>): ValidateFunction {
  const key = JSON.stringify(schema);
  const existing = compiled.get(key);
  if (existing !== undefined) return existing;
  const validate = ajv.compile(schema);
  compiled.set(key, validate);
  return validate;
}

function errorsOf(validate: ValidateFunction): string {
  return (validate.errors ?? []).map((error) => `${error.instancePath || "/"} ${error.message ?? ""}`).join("; ");
}
