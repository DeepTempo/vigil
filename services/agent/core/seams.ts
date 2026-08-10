import type { AgentEvent, NewEvent, TerminalPayload } from "../contracts/events.js";
import type { RegisteredTool, ToolResult } from "../contracts/tool.js";

// The four seams of ADR-0002, as ports the harness receives rather than builds.
// Budget is already a contract (#589) and is re-exported so a caller wires all
// four from one module.
export type { Budget, BudgetLimits, Refusal, Reservation, Spend, SpendPayload, TokenCounts } from "../contracts/budget.js";

// Null by default. The architecture document calls the component this would
// otherwise bind to brittle, and a contract shaped by the thing being replaced
// is the wrong contract, so recall returns nothing until something real lands.
export interface Memory {
  recall(cue: string, limit: number): Promise<readonly string[]>;
  remember(note: string): Promise<void>;
}

// Deliberately the public surface of the ledger repository, so the Postgres
// implementation satisfies this port with no adapter and no edit to it. seq is
// assigned by the implementation: no caller chooses its own position in the log.
export interface State<Kinds extends Record<string, unknown> = Record<never, never>> {
  latestSeq(runId: string): Promise<number | null>;
  read(runId: string): Promise<AgentEvent<Kinds>[]>;
  append(runId: string, from: number, events: readonly NewEvent<Kinds>[]): Promise<number>;
  terminal(runId: string): Promise<TerminalPayload | null>;
}

// How a call reaches its adapter, and nothing more. It never scans or renders
// what it returns: the harness does that to whatever comes back, which is why
// no implementation of this port can opt a result out of being scanned.
export interface ToolDispatch {
  invoke(tool: RegisteredTool, args: Record<string, unknown>): Promise<ToolResult>;
}
