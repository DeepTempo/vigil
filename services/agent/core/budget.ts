import {
  ZERO_TOKENS,
  type Budget,
  type BudgetLimits,
  type Quota,
  type Refusal,
  type Spend,
  type SpendPayload,
  type TokenCounts,
} from "../contracts/budget.js";

export function addTokens(left: TokenCounts, right: TokenCounts): TokenCounts {
  return {
    input: left.input + right.input,
    output: left.output + right.output,
    cache_read: left.cache_read + right.cache_read,
    cache_write: left.cache_write + right.cache_write,
  };
}

// Nothing to ask, so cost is held against the pool's own total rather than the
// gateway's. For tests and for any deployment running without a gateway key.
export const unmeteredQuota: Quota = { spent: async () => null };

// What the run has spent, read off its own ledger. One spend event is one model
// call, so the count is the call count -- the same thing beginCall increments,
// which is why a resumed run continues its allowance rather than restarting it.
export function seedFrom(events: readonly SpentEvent[]): Seed {
  let spent: Spend = { calls: 0, cost_usd: 0, tokens: ZERO_TOKENS };
  let started = 0;

  for (const event of events) {
    if (event.kind === "run") started = Date.parse(event.ts);
    if (event.kind !== "spend") continue;
    const payload = event.payload as SpendPayload;
    spent = {
      calls: spent.calls + 1,
      cost_usd: spent.cost_usd + (payload.cost_usd ?? 0),
      tokens: addTokens(spent.tokens, payload.tokens),
    };
  }
  return { spent, started };
}

// Structural rather than AgentEvent<Kinds>: the fold reads two kinds and a
// timestamp, and never needs to know whose ledger it is walking.
export interface SpentEvent {
  kind: string;
  ts: string;
  payload: unknown;
}

// What a run has already spent and when it began, folded from its ledger. A pool
// built without one is a pool that starts a resumed run's allowance over, so a
// run killed near its ceiling would come back with a full budget every time.
export interface Seed {
  spent: Spend;
  started: number;
}

export const FRESH: Seed = { spent: { calls: 0, cost_usd: 0, tokens: ZERO_TOKENS }, started: 0 };

// One pool per run. Calls and elapsed time are counted here because no gateway
// knows either; dollars are read from the gateway when it can be reached, and
// held against the local total when it cannot.
export function budgetOf(
  limits: BudgetLimits,
  quota: Quota,
  providerType: string,
  now = Date.now,
  seed: Seed = FRESH,
): Budget {
  return new Pool(limits, quota, providerType, now, seed);
}

class Pool implements Budget {
  private calls: number;
  private cost: number;
  private tokens: TokenCounts;
  private readonly started: number;

  constructor(
    readonly limits: BudgetLimits,
    private readonly quota: Quota,
    private readonly providerType: string,
    private readonly now: () => number,
    seed: Seed,
  ) {
    this.calls = seed.spent.calls;
    this.cost = seed.spent.cost_usd;
    this.tokens = seed.spent.tokens;
    // The run's own start, not this process's: a resume that restarted the clock
    // would hand a killed run a fresh wall-time allowance on every attempt.
    this.started = seed.started === 0 ? now() : seed.started;
  }

  get spent(): Spend {
    return { calls: this.calls, cost_usd: this.cost, tokens: { ...this.tokens } };
  }

  // Wall before cost: a run already over time should not spend a gateway round
  // trip finding out it is also over budget.
  async beginCall(): Promise<Refusal | null> {
    const limit = this.limits.max_calls;
    if (this.calls >= limit) return { reason: "calls_exhausted", used: this.calls, limit };

    const used_ms = this.now() - this.started;
    if (used_ms >= this.limits.max_wall_ms) {
      return { reason: "wall_exhausted", used_ms, limit_ms: this.limits.max_wall_ms };
    }

    const refusal = await this.overspent();
    if (refusal !== null) return refusal;

    this.calls += 1;
    return null;
  }

  record(payload: SpendPayload): void {
    this.tokens = addTokens(this.tokens, payload.tokens);
    if (payload.cost_usd !== null) this.cost += payload.cost_usd;
  }

  // An unreadable quota is not a refusal, but it is not a licence either: the
  // local total is held against max_cost_usd whether or not the gateway answers.
  // Without that, every deployment running on unmeteredQuota -- which is all of
  // them -- has no cost ceiling at all, and the seeded total nothing reads.
  private async overspent(): Promise<Refusal | null> {
    const reported = await this.quota.spent();
    if (reported === null) {
      const limit_usd = this.limits.max_cost_usd;
      if (this.cost < limit_usd) return null;
      return { reason: "cost_exhausted", used_usd: this.cost, limit_usd };
    }

    // The gateway prices, so where it and the fold disagree it is the authority.
    this.cost = reported.used_usd;
    const limit_usd = Math.min(this.limits.max_cost_usd, reported.limit_usd);
    if (reported.used_usd < limit_usd) return null;
    return { reason: "cost_exhausted", used_usd: reported.used_usd, limit_usd };
  }

  payloadFor(model_id: string, role: string, tokens: TokenCounts, cost_usd: number | null): SpendPayload {
    return { model_id, provider_type: this.providerType, role, tokens, cost_usd };
  }
}
