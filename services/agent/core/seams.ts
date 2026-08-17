import type { AgentEvent, NewEvent, TerminalPayload } from "../contracts/events.js";
import type { RegisteredTool, ToolResult } from "../contracts/tool.js";

// The four seams as ports the harness receives rather than builds. Budget is
// already a contract, re-exported so a caller wires all four from one module.
export type { Budget, BudgetLimits, Quota, Refusal, Spend, SpendPayload, TokenCounts } from "../contracts/budget.js";

// Null by default: a contract shaped by the component being replaced is the wrong
// contract, so recall returns nothing until something real lands.
export interface Memory {
  recall(cue: string, limit: number): Promise<readonly string[]>;
  remember(note: string): Promise<void>;
}

// Snapshots are excluded unless asked for, and `since` reads only what is new.
// The fold runs once per tool turn, so a full read there is quadratic in a run.
export interface ReadOptions {
  since?: number;
  snapshots?: boolean;
}

// Deliberately the ledger repository's public surface, so Postgres satisfies it with
// no adapter. The store assigns seq: a position read before a turn is stale after it.
export interface State<Kinds extends Record<string, unknown> = Record<never, never>> {
  latestSeq(runId: string): Promise<number | null>;
  read(runId: string, opts?: ReadOptions): Promise<AgentEvent<Kinds>[]>;
  append(runId: string, events: readonly NewEvent<Kinds>[]): Promise<number>;
  terminal(runId: string): Promise<TerminalPayload | null>;
}

// How a call reaches its adapter, nothing more; it never scans or renders. The
// signal is the run's: a worker that lost its lease drops the calls in flight.
export interface ToolDispatch {
  invoke(tool: RegisteredTool, args: Record<string, unknown>, signal?: AbortSignal): Promise<ToolResult>;
}
