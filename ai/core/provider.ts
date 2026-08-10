import { ZERO_TOKENS, type TokenCounts } from "../contracts/budget.js";

export interface ToolCall {
  id: string;
  tool: string;
  args: string;
}

// The harness's own message shape rather than a vendor's, so the loop imports no
// SDK and a second surface or a scripted provider is a drop-in.
export type Message =
  | { role: "system" | "user"; content: string }
  | { role: "assistant"; content: string; tool_calls: readonly ToolCall[] }
  | { role: "tool"; call_id: string; content: string };

export interface ToolSchema {
  id: string;
  description: string;
  parameters: Record<string, unknown>;
}

export interface TurnRequest {
  messages: readonly Message[];
  tools: readonly ToolSchema[];
  // Set on the emission turn: the provider must answer against this schema and
  // offer no tools. Combining tools with a strict output format degrades
  // unpredictably across the providers the gateway fronts, and a silent schema
  // violation is the worst failure available here.
  emit?: Record<string, unknown>;
  signal?: AbortSignal;
}

export interface Turn {
  content: string;
  tool_calls: readonly ToolCall[];
  tokens: TokenCounts;
}

// Exactly one model call. The loop around it belongs to the harness, which is
// what keeps the turn cap, the approval gate and the injection scan on this side
// of the seam rather than inside a provider a workflow could swap.
export interface Provider {
  readonly model: string;
  turn(request: TurnRequest): Promise<Turn>;
}

// Carries what was already burned, so a call that fails does not drop spend the
// budget still has to account for.
export class ProviderError extends Error {
  constructor(
    message: string,
    readonly tokens: TokenCounts = ZERO_TOKENS,
  ) {
    super(message);
  }
}
