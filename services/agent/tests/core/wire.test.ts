import { beforeEach, describe, expect, it } from "vitest";
import type OpenAI from "openai";
import { Limiter } from "../../core/limiter.js";
import { EMIT_TOOL, openAiSurface, resetEmitMode } from "../../core/wire.js";
import type { Message } from "../../core/provider.js";

type Body = OpenAI.Chat.ChatCompletionCreateParamsNonStreaming;

const SCHEMA = { type: "object", required: ["verb"], properties: { verb: { type: "string" } } };

function limiter(): Limiter {
  return new Limiter({ rpm: 10_000, tpm: 10_000_000 }, 4, 1);
}

function completion(message: Record<string, unknown>, usage?: Record<string, unknown>): OpenAI.Chat.ChatCompletion {
  return {
    choices: [{ message, finish_reason: "stop", index: 0, logprobs: null }],
    usage: usage ?? { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
  } as unknown as OpenAI.Chat.ChatCompletion;
}

function surfaceOf(create: (body: Body) => Promise<OpenAI.Chat.ChatCompletion>, model = "openai/gpt-4o") {
  const client = { chat: { completions: { create } } } as unknown as OpenAI;
  return openAiSurface(client, model, limiter(), "openai");
}

beforeEach(() => resetEmitMode());

describe("the OpenAI surface", () => {
  it("makes one call and hands back what the model said", async () => {
    const bodies: Body[] = [];
    const surface = surfaceOf(async (body) => {
      bodies.push(body);
      return completion({ role: "assistant", content: "thinking about it" });
    });

    const turn = await surface.turn({ messages: [{ role: "user", content: "go" }], tools: [] });
    expect(turn.content).toBe("thinking about it");
    expect(turn.tool_calls).toEqual([]);
    expect(bodies).toHaveLength(1);
    expect(bodies[0]!.max_tokens).toBeGreaterThan(4096);
    // No tools offered means the key is absent, not present and empty: some
    // providers reject an empty tools array outright.
    expect(bodies[0]!.tools).toBeUndefined();
  });

  it("reports tool calls the model asked for", async () => {
    const surface = surfaceOf(async () =>
      completion({
        role: "assistant",
        content: null,
        tool_calls: [{ id: "c1", type: "function", function: { name: "bump", arguments: '{"by":1}' } }],
      }),
    );

    const turn = await surface.turn({
      messages: [{ role: "user", content: "go" }],
      tools: [{ id: "bump", description: "increment", parameters: {} }],
    });
    expect(turn.tool_calls).toEqual([{ id: "c1", tool: "bump", args: '{"by":1}' }]);
  });

  // Handed to JSON.parse a block list stringifies to [object Object], so an
  // answer the model got right would be discarded as invalid JSON.
  it("flattens a reply that arrives as content blocks", async () => {
    const surface = surfaceOf(async () =>
      completion({ role: "assistant", content: [{ type: "text", text: '{"verb":' }, { type: "text", text: '"HALT"}' }] }),
    );
    const turn = await surface.turn({ messages: [{ role: "user", content: "go" }], tools: [], emit: SCHEMA });
    expect(turn.content).toBe('{"verb":"HALT"}');
  });

  it("carries the transcript back to the wire, tool turns included", async () => {
    const bodies: Body[] = [];
    const surface = surfaceOf(async (body) => {
      bodies.push(body);
      return completion({ role: "assistant", content: "done" });
    });

    const messages: Message[] = [
      { role: "system", content: "be brief" },
      { role: "user", content: "go" },
      { role: "assistant", content: "", tool_calls: [{ id: "c1", tool: "bump", args: "{}" }] },
      { role: "tool", call_id: "c1", content: "1 row" },
    ];
    await surface.turn({ messages, tools: [] });

    const sent = bodies[0]!.messages;
    expect(sent.map((message) => message.role)).toEqual(["system", "user", "assistant", "tool"]);
    expect(sent[2]).toEqual({
      role: "assistant",
      content: "",
      tool_calls: [{ id: "c1", type: "function", function: { name: "bump", arguments: "{}" } }],
    });
    expect(sent[3]).toEqual({ role: "tool", tool_call_id: "c1", content: "1 row" });
  });
});

describe("the emission turn", () => {
  it("asks for a schema-constrained answer and offers no tools", async () => {
    const bodies: Body[] = [];
    const surface = surfaceOf(async (body) => {
      bodies.push(body);
      return completion({ role: "assistant", content: '{"verb":"HALT"}' });
    });

    await surface.turn({
      messages: [{ role: "user", content: "go" }],
      tools: [{ id: "bump", description: "increment", parameters: {} }],
      emit: SCHEMA,
    });
    expect(bodies[0]!.response_format).toBeDefined();
    expect(bodies[0]!.tools).toBeUndefined();
  });

  it("downgrades to a tool-shaped emit when the gateway rejects the format, once", async () => {
    const bodies: Body[] = [];
    const surface = surfaceOf(async (body) => {
      bodies.push(body);
      if (body.response_format !== undefined) throw Object.assign(new Error("unsupported"), { status: 400 });
      return completion({
        role: "assistant",
        tool_calls: [{ id: "e1", type: "function", function: { name: EMIT_TOOL, arguments: '{"verb":"HALT"}' } }],
      });
    });

    const request = { messages: [{ role: "user" as const, content: "go" }], tools: [], emit: SCHEMA };
    // The arguments come back as content, so the loop validates one shape
    // whichever mode produced it.
    expect((await surface.turn(request)).content).toBe('{"verb":"HALT"}');
    expect((await surface.turn(request)).tool_calls).toEqual([]);

    // Remembered, so the second emission never probes response_format again.
    expect(bodies.filter((body) => body.response_format !== undefined)).toHaveLength(1);
    expect(bodies.at(-1)!.tool_choice).toEqual({ type: "function", function: { name: EMIT_TOOL } });
  });

  // Remembered per model: response_format is a property of the provider behind
  // one model name, so one gateway's 400 must not downgrade every other model.
  it("does not downgrade a different model on another's rejection", async () => {
    const bodies: Body[] = [];
    const reject = async (body: Body) => {
      bodies.push(body);
      if (body.response_format !== undefined) throw Object.assign(new Error("unsupported"), { status: 400 });
      return completion({
        role: "assistant",
        tool_calls: [{ id: "e1", type: "function", function: { name: EMIT_TOOL, arguments: "{}" } }],
      });
    };

    await surfaceOf(reject, "legacy/model").turn({ messages: [], tools: [], emit: SCHEMA });
    bodies.length = 0;
    await surfaceOf(reject, "openai/gpt-4o").turn({ messages: [], tools: [], emit: SCHEMA });
    expect(bodies[0]!.response_format).toBeDefined();
  });

  it("does not read a non-400 failure as a reason to downgrade", async () => {
    const surface = surfaceOf(async () => {
      throw Object.assign(new Error("unauthorized"), { status: 401 });
    });
    await expect(surface.turn({ messages: [], tools: [], emit: SCHEMA })).rejects.toThrow(/unauthorized/);
  });
});

describe("token accounting", () => {
  it("reads the cached share from whichever surface reported it", async () => {
    const openai = await surfaceOf(async () =>
      completion({ role: "assistant", content: "ok" }, {
        prompt_tokens: 100,
        completion_tokens: 20,
        prompt_tokens_details: { cached_tokens: 60 },
      }),
    ).turn({ messages: [], tools: [] });
    expect(openai.tokens).toEqual({ input: 100, output: 20, cache_read: 60, cache_write: 0 });

    const alternate = await surfaceOf(async () =>
      completion({ role: "assistant", content: "ok" }, {
        prompt_tokens: 40,
        completion_tokens: 8,
        cache_read_input_tokens: 10,
        cache_creation_input_tokens: 30,
      }),
    ).turn({ messages: [], tools: [] });
    // input is the total, so Anthropic's two cache counters are added back;
    // natively input_tokens excludes both and the call would price two ways.
    expect(alternate.tokens).toEqual({ input: 80, output: 8, cache_read: 10, cache_write: 30 });
  });

  // The OpenAI route already counts the cached share inside prompt_tokens, so
  // adding it back there would bill it twice.
  it("does not double-count a cached share the OpenAI route already included", async () => {
    const turn = await surfaceOf(async () =>
      completion({ role: "assistant", content: "ok" }, {
        prompt_tokens: 100,
        completion_tokens: 20,
        prompt_tokens_details: { cached_tokens: 90 },
      }),
    ).turn({ messages: [], tools: [] });
    expect(turn.tokens.input).toBe(100);
    expect(turn.tokens.cache_read).toBe(90);
  });

  it("reports zeroes rather than guessing when usage is absent", async () => {
    const turn = await surfaceOf(async () =>
      ({ choices: [{ message: { role: "assistant", content: "ok" }, finish_reason: "stop", index: 0 }] }) as unknown as OpenAI.Chat.ChatCompletion,
    ).turn({ messages: [], tools: [] });
    expect(turn.tokens).toEqual({ input: 0, output: 0, cache_read: 0, cache_write: 0 });
  });
});
