import type { AgentEvent, NewEvent, TerminalPayload } from "../contracts/events.js";
import type { RegisteredTool, ToolResult } from "../contracts/tool.js";

// The four seams as ports the harness receives rather than builds. Budget is
// already a contract, re-exported so a caller wires all four from one module.
export type { Budget, BudgetLimits, Refusal, Reservation, Spend, SpendPayload, TokenCounts } from "../contracts/budget.js";

// Null by default: a contract shaped by the component being replaced is the wrong
// contract, so recall returns nothing until something real lands.
export interface Memory {
  recall(cue: string, limit: number): Promise<readonly string[]>;
  remember(note: string): Promise<void>;
}

// Deliberately the ledger repository's public surface, so Postgres satisfies it
// with no adapter. seq is assigned here: no caller picks its position in the log.
export interface State<Kinds extends Record<string, unknown> = Record<never, never>> {
  latestSeq(runId: string): Promise<number | null>;
  read(runId: string): Promise<AgentEvent<Kinds>[]>;
  append(runId: string, from: number, events: readonly NewEvent<Kinds>[]): Promise<number>;
  terminal(runId: string): Promise<TerminalPayload | null>;
}

// How a call reaches its adapter, nothing more. It never scans or renders, so no
// implementation of this port can opt a result out of being scanned.
export interface ToolDispatch {
  invoke(tool: RegisteredTool, args: Record<string, unknown>): Promise<ToolResult>;
}
