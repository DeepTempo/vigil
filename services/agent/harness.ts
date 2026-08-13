import OpenAI from "openai";
import type { RunKind } from "./contracts/events.js";
import { budgetOf, FRESH, unmeteredQuota, type Seed } from "./core/budget.js";
import { httpPrices } from "./core/prices.js";
import { Limiter } from "./core/limiter.js";
import type { Harness } from "./core/loop.js";
import { nullMemory } from "./core/memory.js";
import { registryOf } from "./core/registry.js";
import { remoteDispatch } from "./core/remote.js";
import type { Memory, State } from "./core/seams.js";
import type { RunSpec } from "./core/spec.js";
import { openAiSurface } from "./core/wire.js";
import { toolsFrom } from "./tools/remote.js";
import { grantsOf as chatGrants } from "./workflows/chat/workflow.js";
import { grantsOf as composeGrants } from "./workflows/compose/workflow.js";
import { grantsOf as leadGrants } from "./workflows/lead/workflow.js";

// One name for the shared secret on both sides of the boundary — Python reads it
// as AGENT_INTERNAL_TOKEN. VIGIL_TOOLS_TOKEN is the older spelling, still read.
export function internalToken(): string {
  return process.env["AGENT_INTERNAL_TOKEN"] ?? process.env["VIGIL_TOOLS_TOKEN"] ?? "";
}

// Which grants a run kind's roles hold. Compose grants per phase agent and chat
// per declared tool, because neither reads a roster the arch wrote.
function grantsFor(kind: RunKind, spec: RunSpec): Record<string, readonly string[]> {
  if (kind === "compose") return composeGrants(spec);
  if (kind === "chat") return chatGrants(spec);
  return leadGrants(spec);
}

// The six injected parts, assembled per run because the model, the grants and the
// budget are all the spec's. Nothing here is shared between two runs.
export function harnessFor<K extends Record<string, unknown>>(
  kind: RunKind,
  spec: RunSpec,
  state: State<K>,
  memory: Memory = nullMemory,
  seed: Seed = FRESH,
): Harness<K> {
  const client = new OpenAI({
    baseURL: process.env["BIFROST_URL"] ?? "http://bifrost:8080",
    apiKey: process.env["BIFROST_API_KEY"] ?? "unused",
  });
  const limiter = new Limiter({ rpm: 500, tpm: 400_000 }, 4);

  return {
    provider: openAiSurface(client, spec.model, limiter, "bifrost"),
    registry: registryOf(toolsFrom(spec.tools), grantsFor(kind, spec)),
    dispatch: remoteDispatch({
      url: process.env["VIGIL_TOOLS_URL"] ?? "http://localhost:6987/internal/tools/invoke",
      token: internalToken(),
    }),
    budget: budgetOf(spec.budgets, unmeteredQuota, Date.now, seed, httpPrices({
      url: process.env["VIGIL_PRICING_URL"] ?? "http://localhost:6987/internal/pricing",
      token: internalToken(),
    })),
    memory,
    state,
  };
}

// Injected so a test drives a run without a provider behind it. The seam is the
// harness itself, which is the only part of a run that reaches outside the process.
export type HarnessFactory = <K extends Record<string, unknown>>(
  kind: RunKind,
  spec: RunSpec,
  state: State<K>,
  memory?: Memory,
  seed?: Seed,
) => Harness<K>;
