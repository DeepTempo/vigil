// One of the four Phase-0 contracts. Consumed by the harness seam and by any
// workflow, which must use it rather than keep parallel accounting.

export interface TokenCounts {
  input: number;
  output: number;
  cache_read: number;
  cache_write: number;
}

// Calls, not decisions: one workflow decision costs several model calls, so a
// deployment meaning decisions must say so where decisions are counted.
//
// max_park_ms is the one the pool does not enforce: how long a run may *wait* is
// the sweeper's to hold, where the other three are the pool's. It lives here
// because it is a ceiling on the run, journaled with the rest into the run event,
// and tightened per run through the same overrides path.
export interface BudgetLimits {
  max_calls: number;
  max_cost_usd: number;
  max_wall_ms: number;
  max_park_ms: number;
}

// Seven days to answer a checkpoint. Long, because abandoning a run journals a
// terminal and no answer reaches it afterwards -- but not unbounded, because a
// checkpoint answered three weeks late resumes a run whose transcript describes
// a world that has moved on. Required rather than optional so that a deployment
// abandoning runs after a week is something a config said, not something it
// inherited without being asked.
export const DEFAULT_PARK_MS = 604_800_000;

export interface Spend {
  calls: number;
  cost_usd: number;
  tokens: TokenCounts;
}

// One model call, journaled. Tokens come from the provider and are exact here; cost
// is the backend catalog's rates applied to them, and null when nothing could be
// asked -- an unpriced call is still a call, and losing the tokens to a pricing
// outage would be worse than not knowing the dollars.
export interface SpendPayload {
  model_id: string;
  provider_type: string;
  role: string;
  tokens: TokenCounts;
  cost_usd: number | null;
  // How the rates resolved -- "exact", "heuristic", "zero", "unknown" -- or null
  // when nothing priced it. A $0.00 from a real catalog entry and a $0.00 nobody
  // could price are the same number and nothing alike, and a record of money should
  // say which it is holding.
  pricing_source: string | null;
}

// A value, never a throw: the exhaustiveness argument applies here or nowhere.
export type Refusal =
  | { reason: "calls_exhausted"; used: number; limit: number }
  | { reason: "cost_exhausted"; used_usd: number; limit_usd: number }
  | { reason: "wall_exhausted"; used_ms: number; limit_ms: number };

// What the gateway says has been spent against this run's key. Returning null
// means it could not be read, which is not a refusal: the gateway still caps.
export interface Quota {
  spent(): Promise<{ used_usd: number; limit_usd: number } | null>;
}

// Calls and wall are the harness's to count, dollars the gateway's to enforce.
// Checked once per call, so an exhausted run parks before paying for another.
export interface Budget {
  readonly limits: BudgetLimits;
  readonly spent: Spend;
  beginCall(): Promise<Refusal | null>;
  record(payload: SpendPayload): void;
  // What a call cost, so the loop can journal it and the pool can hold it against
  // max_cost_usd. Here rather than on the harness because money is the budget's:
  // this is the object that already owns the ceiling and the running total.
  priceOf(modelId: string, providerType: string, tokens: TokenCounts): Promise<Priced>;
}

// Null cost means nothing could price it, which is not zero. The two are told apart
// everywhere downstream, so they are told apart here first.
export interface Priced {
  cost_usd: number | null;
  source: string | null;
}

export const ZERO_TOKENS: TokenCounts = { input: 0, output: 0, cache_read: 0, cache_write: 0 };
