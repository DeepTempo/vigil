import { describe, expect, it } from "vitest";
import { archFor } from "../../arch/registry.js";
import type { SpendPayload } from "../../contracts/budget.js";
import { defineTool, type RegisteredTool, type ToolResult } from "../../contracts/tool.js";
import { budgetOf, unmeteredQuota } from "../../core/budget.js";
import { localDispatch } from "../../core/dispatch.js";
import type { Harness } from "../../core/loop.js";
import { nullMemory } from "../../core/memory.js";
import { registryOf } from "../../core/registry.js";
import { assembleSpec, loadArch, parseConfig, parsePlaybook, SpecError, type RunSpec } from "../../core/spec.js";
import { InProcessState } from "../../core/state.js";
import type { StreamEvent } from "../../core/stream.js";
import { conversationOf, grantsOf, runChat, type ChatReport, type Turn } from "../../workflows/chat/workflow.js";
import { scriptedProvider, type ScriptedProvider, type ScriptedTurn } from "../support/scripted-provider.js";

const RUN = "5a2c2d3e-0000-4000-8000-000000000631";
const ASKED: Turn[] = [{ role: "user", content: "is 10.0.0.4 talking to anything odd?" }];

const CONFIG = `
model: anthropic/claude-opus-5
budgets: { max_calls: 6, max_wall_ms: 600000, max_cost_usd: 1.00 }
runtime: { max_turns: 4, result_cap: 8000, recall_limit: 2 }
tools:
  - id: findings
    kind: remote
    description: search findings
    parameters: { type: object }
approvals: []
`;

const LOOKUP: RegisteredTool = defineTool(
  {
    id: "findings",
    description: "search findings",
    parameters: { type: "object" },
    execute: async (): Promise<ToolResult> => ({ ok: true, rows: [{ host: "10.0.0.4" }], rowCount: 1, capped: false, sourceSystem: "test" }),
  },
  { maxRows: 10, timeoutMs: 500 },
);

function specOf(config = CONFIG): RunSpec {
  const entry = archFor("chat");
  return assembleSpec({
    arch: loadArch(entry.arch, entry.actions),
    playbook: parsePlaybook(""),
    config: parseConfig(config),
    prompt: "",
  });
}

function harnessOf(script: readonly ScriptedTurn[], state = new InProcessState()): Harness {
  return {
    provider: scriptedProvider(script),
    registry: registryOf([LOOKUP], grantsOf(specOf())),
    dispatch: localDispatch,
    budget: budgetOf({ max_calls: 6, max_cost_usd: 1, max_wall_ms: 600_000 }, unmeteredQuota, "scripted"),
    memory: nullMemory,
    state,
  };
}

async function converse(harness: Harness, turns: readonly Turn[] = ASKED): Promise<{ seen: StreamEvent<string>[]; report: ChatReport }> {
  const stream = runChat(harness, { run_id: RUN, spec: specOf(), turns });
  const seen: StreamEvent<string>[] = [];
  for (;;) {
    const next = await stream.next();
    if (next.done) return { seen, report: next.value };
    seen.push(next.value);
  }
}

describe("a chat turn on the harness", () => {
  it("answers in prose, streaming the text as it arrives", async () => {
    const harness = harnessOf([{ deltas: ["nothing ", "unusual"] }]);
    const { seen, report } = await converse(harness);

    expect(report.status).toBe("completed");
    expect(report.answer).toBe("nothing unusual");
    expect(seen.filter((event) => event.type === "text_delta").map((event) => event.text)).toEqual(["nothing ", "unusual"]);
  });

  it("calls tools first and answers over what they returned", async () => {
    const harness = harnessOf([{ calls: [{ tool: "findings", args: "{}" }] }, { content: "one finding on that host" }]);
    const { seen, report } = await converse(harness);

    expect(seen.some((event) => event.type === "tool_call")).toBe(true);
    expect(report.answer).toBe("one finding on that host");
  });

  it("grants the lead every tool the config declared, because the config is the request", () => {
    expect(grantsOf(specOf())).toEqual({ lead: ["findings"] });
  });
});

describe("the conversation is the run", () => {
  it("opens the ledger once and leaves it open, because the person may say more", async () => {
    const state = new InProcessState();
    await converse(harnessOf([{ content: "first" }], state));
    await converse(harnessOf([{ content: "second" }], state));

    const events = await state.read(RUN);
    expect(events.filter((event) => event.kind === "run")).toHaveLength(1);
    // No terminal: a conversation that ended is a conversation nobody continued.
    expect(events.filter((event) => event.kind === "terminal")).toHaveLength(0);
  });

  it("journals what the turn spent", async () => {
    const state = new InProcessState();
    await converse(harnessOf([{ content: "ok", tokens: { input: 40, output: 4 } }], state));

    const spend = (await state.read(RUN)).filter((event) => event.kind === "spend");
    expect(spend).toHaveLength(1);
    expect((spend[0]!.payload as SpendPayload).tokens.input).toBe(40);
  });

  it("keeps the spend when the reader walks away mid-answer", async () => {
    const state = new InProcessState();
    const stream = runChat(harnessOf([{ deltas: ["par", "tial"] }], state), { run_id: RUN, spec: specOf(), turns: ASKED });

    // Read as far as the provider reporting what it burned, then abandon the
    // stream the way a dropped connection does.
    for (;;) {
      const next = await stream.next();
      if (next.done || next.value.type === "usage") break;
    }
    await stream.return(undefined as never);

    const spend = (await state.read(RUN)).filter((event) => event.kind === "spend");
    expect(spend).toHaveLength(1);
  });
});

describe("what the workflow refuses", () => {
  it("refuses an arch whose lead answers in JSON", () => {
    const spec = { ...specOf(), roles: { workers: {}, lead: { prompt: "x", description: "", output_schema: {}, tools: [] } } };
    const stream = runChat(harnessOf([]), { run_id: RUN, spec, turns: ASKED });
    return expect(stream.next()).rejects.toThrow(SpecError);
  });

  it("refuses a turn with nothing said in it", () => {
    const stream = runChat(harnessOf([]), { run_id: RUN, spec: specOf(), turns: [] });
    return expect(stream.next()).rejects.toThrow(/needs at least one message/);
  });
});

describe("the opening turn is the one the prefix caches on", () => {
  it("splits the posted conversation into an opening and the history behind it", () => {
    const { task, history } = conversationOf([
      { role: "user", content: "first" },
      { role: "assistant", content: "answered" },
      { role: "user", content: "and now?" },
    ]);

    expect(task).toBe("first");
    expect(history).toEqual([
      { role: "assistant", content: "answered", tool_calls: [] },
      { role: "user", content: "and now?" },
    ]);
  });

  it("sends the same opening bytes however far the conversation has run", async () => {
    const opening = async (turns: readonly Turn[]) => {
      const harness = harnessOf([{ content: "ok" }]);
      await converse(harness, turns);
      return (harness.provider as ScriptedProvider).requests[0]!.messages.slice(0, 2);
    };

    expect(await opening(ASKED)).toEqual(
      await opening([...ASKED, { role: "assistant", content: "nothing odd" }, { role: "user", content: "sure?" }]),
    );
  });
});
