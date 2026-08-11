// One of the four Phase-0 contracts. Consumed by the harness seam and by any
// workflow, which must use it rather than keep parallel accounting.

export interface TokenCounts {
  input: number;
  output: number;
  cache_read: number;
  cache_write: number;
}

export interface BudgetLimits {
  max_iterations: number;
  max_cost_usd: number;
}

export interface Spend {
  iterations: number;
  cost_usd: number;
  tokens: TokenCounts;
}

// One model call, journaled. Tokens come from the provider and are exact here;
// cost is null until the gateway reports it, because the gateway prices, not us.
export interface SpendPayload {
  model_id: string;
  provider_type: string;
  role: string;
  tokens: TokenCounts;
  cost_usd: number | null;
}

// A value, never a throw: the exhaustiveness argument applies here or nowhere.
export type Refusal =
  | { reason: "iterations_exhausted"; used: number; limit: number }
  | { reason: "cost_exhausted"; used_usd: number; limit_usd: number };

// What the gateway says has been spent against this run's key. Returning null
// means it could not be read, which is not a refusal: the gateway still caps.
export interface Quota {
  spent(): Promise<{ used_usd: number; limit_usd: number } | null>;
}

// Iterations are the harness's to count, dollars the gateway's to enforce. Quota
// is read once per iteration, so an exhausted run parks before paying for one.
export interface Budget {
  readonly limits: BudgetLimits;
  readonly spent: Spend;
  beginIteration(): Promise<Refusal | null>;
  record(payload: SpendPayload): void;
}

export const ZERO_TOKENS: TokenCounts = { input: 0, output: 0, cache_read: 0, cache_write: 0 };
