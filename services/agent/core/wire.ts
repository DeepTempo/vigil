import OpenAI from "openai";
import type { TokenCounts } from "../contracts/budget.js";
import { estimateTokens, Limiter, statusOf } from "./limiter.js";
import {
  ProviderError,
  type Message,
  type Provider,
  type ToolCall,
  type ToolSchema,
  type Turn,
  type TurnRequest,
} from "./provider.js";

// Unset, the gateway's own default cuts a long emission off mid-JSON, which
// arrives as an unparseable answer rather than as a limit that was hit.
const MAX_OUTPUT_TOKENS = 12_000;

export const EMIT_TOOL = "emit";

type Body = OpenAI.Chat.ChatCompletionCreateParamsNonStreaming;

// Not every provider honours response_format, so a 400 downgrades once to a tool
// whose parameters are the schema. Remembered per model, never process-wide.
const emitModes = new Map<string, "schema" | "tool">();

export function resetEmitMode(): void {
  emitModes.clear();
}

export function openAiSurface(client: OpenAI, model: string, limiter: Limiter): Provider {
  return new OpenAiSurface(client, model, limiter);
}

// The one surface built. The gateway routes to either provider family behind a
// model name, so a second wire buys nothing until cache_control and thinking.
class OpenAiSurface implements Provider {
  constructor(
    private readonly client: OpenAI,
    readonly model: string,
    private readonly limiter: Limiter,
  ) {}

  async turn(request: TurnRequest): Promise<Turn> {
    if (request.emit !== undefined) return this.emit(request, request.emit);
    const tools = request.tools.length === 0 ? {} : { tools: wireTools(request.tools) };
    return turnOf(await this.call({ model: this.model, messages: wire(request.messages), ...tools }, request.signal));
  }

  private async emit(request: TurnRequest, schema: Record<string, unknown>): Promise<Turn> {
    const messages = wire(request.messages);
    if ((emitModes.get(this.model) ?? "schema") === "schema") {
      try {
        const format = { type: "json_schema" as const, json_schema: { name: "emission", strict: false, schema } };
        return turnOf(await this.call({ model: this.model, messages, response_format: format }, request.signal));
      } catch (error) {
        if (statusOf(error) !== 400) throw error;
        emitModes.set(this.model, "tool");
      }
    }

    const emit = { name: EMIT_TOOL, description: "Emit your answer.", parameters: schema };
    const turn = turnOf(
      await this.call(
        {
          model: this.model,
          messages,
          tools: [{ type: "function", function: emit }],
          tool_choice: { type: "function", function: { name: EMIT_TOOL } },
        },
        request.signal,
      ),
    );
    // The emission arrived as the tool's arguments. It is returned as content so
    // the loop validates one shape whichever mode produced it.
    const emitted = turn.tool_calls.find((call) => call.tool === EMIT_TOOL);
    return { ...turn, content: emitted === undefined ? turn.content : emitted.args, tool_calls: [] };
  }

  private async call(body: Body, signal?: AbortSignal): Promise<OpenAI.Chat.ChatCompletion> {
    // Before the limiter, not only inside the request: a call still queued behind
    // a rate limit is the cheapest one to give up on.
    signal?.throwIfAborted();
    const response = await this.limiter.run(estimateTokens(JSON.stringify(body)), () =>
      this.client.chat.completions.create({ max_tokens: MAX_OUTPUT_TOKENS, ...body }, signal ? { signal } : {}),
    );
    if (!("choices" in response)) throw new ProviderError("streaming responses are not supported");
    return response;
  }
}

function turnOf(response: OpenAI.Chat.ChatCompletion): Turn {
  const tokens = tokensOf(response.usage);
  const message = response.choices[0]?.message;
  if (message === undefined) throw new ProviderError("the model returned no message", tokens);
  return { content: textOf(message.content), tool_calls: callsOf(message.tool_calls), tokens };
}

function callsOf(calls: OpenAI.Chat.ChatCompletionMessageToolCall[] | undefined): ToolCall[] {
  return (calls ?? []).flatMap((call) =>
    call.type === "function" ? [{ id: call.id, tool: call.function.name, args: call.function.arguments }] : [],
  );
}

// Some providers reply with a content-block list. Handing an array to JSON.parse
// stringifies it to [object Object], throwing away an answer the model got right.
function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((block) => (typeof block === "object" && block !== null ? String((block as { text?: unknown }).text ?? "") : ""))
    .join("");
}

// Two surfaces disagreeing about an input token, normalised so input is always the
// total: OpenAI already counts the cached share, Anthropic excludes both counters.
function tokensOf(usage: OpenAI.CompletionUsage | undefined): TokenCounts {
  const alternate = usage as
    | (typeof usage & { cache_read_input_tokens?: number; cache_creation_input_tokens?: number })
    | undefined;
  const reported = usage?.prompt_tokens ?? 0;
  const native = alternate?.cache_read_input_tokens !== undefined || alternate?.cache_creation_input_tokens !== undefined;
  const cache_read = usage?.prompt_tokens_details?.cached_tokens ?? alternate?.cache_read_input_tokens ?? 0;
  const cache_write = alternate?.cache_creation_input_tokens ?? 0;
  return {
    input: native ? reported + cache_read + cache_write : reported,
    output: usage?.completion_tokens ?? 0,
    cache_read,
    cache_write,
  };
}

function wire(messages: readonly Message[]): OpenAI.Chat.ChatCompletionMessageParam[] {
  return messages.map((message) => {
    if (message.role === "tool") return { role: "tool", tool_call_id: message.call_id, content: message.content };
    if (message.role !== "assistant") return { role: message.role, content: message.content };
    if (message.tool_calls.length === 0) return { role: "assistant", content: message.content };
    return { role: "assistant", content: message.content, tool_calls: message.tool_calls.map(wireCall) };
  });
}

function wireCall(call: ToolCall): OpenAI.Chat.ChatCompletionMessageToolCall {
  return { id: call.id, type: "function", function: { name: call.tool, arguments: call.args } };
}

function wireTools(tools: readonly ToolSchema[]): OpenAI.Chat.ChatCompletionTool[] {
  return tools.map((tool) => ({
    type: "function",
    function: { name: tool.id, description: tool.description, parameters: tool.parameters },
  }));
}
