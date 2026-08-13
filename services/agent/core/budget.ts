import {
  ZERO_TOKENS,
  type Budget,
  type BudgetLimits,
  type Priced,
  type Quota,
  type Refusal,
  type Spend,
  type SpendPayload,
  type TokenCounts,
} from "../contracts/budget.js";
import { costOf, noPrices, type Prices } from "./prices.js";

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
export function seedFrom(events: readonly SpentEvent[], now = Date.now()): Seed {
  let spent: Spend = { calls: 0, cost_usd: 0, tokens: ZERO_TOKENS };
  let opened = 0;

  for (const event of events) {
    if (event.kind === "run") opened = Date.parse(event.ts);
    if (event.kind !== "spend") continue;
    const payload = event.payload as SpendPayload;
    spent = {
      calls: spent.calls + 1,
      cost_usd: spent.cost_usd + (payload.cost_usd ?? 0),
      tokens: addTokens(spent.tokens, payload.tokens),
    };
  }
  return { spent, started: opened === 0 ? 0 : opened + waitedMs(events, now) };
}

interface Wait {
  from: number;
  to: number;
}

// How long the run sat on a checkpoint nobody had answered. A run waiting on a
// human is not a run burning wall time, and the pool's origin is pushed forward by
// this so max_wall_ms measures work rather than patience.
//
// Without it the two ceilings contradict each other: a park TTL of seven days is
// unreachable behind a wall budget of thirty minutes, and every checkpoint answered
// late resumes straight into wall_exhausted -- which is the case the whole resume
// path exists to serve.
//
// Crash time still counts. Only a checkpoint the run itself raised excuses the
// clock, so a worker that died and was reclaimed has spent what it spent, and the
// exploit this seeding closes stays closed.
function waitedMs(events: readonly SpentEvent[], now: number): number {
  const answeredAt = new Map<string, number>();
  for (const event of events) {
    if (event.kind !== "resolution") continue;
    const { checkpoint_id: id } = event.payload as { checkpoint_id?: unknown };
    const at = Date.parse(event.ts);
    if (typeof id === "string" && Number.isFinite(at) && !answeredAt.has(id)) answeredAt.set(id, at);
  }

  // An unanswered checkpoint is still waiting, so its wait runs to now: a resume
  // that arrives before the answer is journaled must not bill the wait it is
  // recovering from.
  const waits: Wait[] = [];
  for (const event of events) {
    if (event.kind !== "checkpoint") continue;
    const { checkpoint_id: id } = event.payload as { checkpoint_id?: unknown };
    const from = Date.parse(event.ts);
    if (typeof id !== "string" || !Number.isFinite(from)) continue;
    const to = answeredAt.get(id) ?? now;
    if (to > from) waits.push({ from, to });
  }

  // Merged rather than summed: two checkpoints open at once waited the same
  // seconds, and counting them twice would hand the run more wall time than it took.
  waits.sort((left, right) => left.from - right.from);
  let total = 0;
  let open: Wait | null = null;
  for (const wait of waits) {
    if (open !== null && wait.from <= open.to) {
      open.to = Math.max(open.to, wait.to);
      continue;
    }
    if (open !== null) total += open.to - open.from;
    open = { ...wait };
  }
  return open === null ? total : total + (open.to - open.from);
}

// Structural rather than AgentEvent<Kinds>: the fold reads two kinds and a
// timestamp, and never needs to know whose ledger it is walking.
export interface SpentEvent {
  kind: string;
  ts: string;
  payload: unknown;
}

// What a run has already spent and when its wall clock began, folded from its
// ledger. A pool built without one is a pool that starts a resumed run's allowance
// over, so a run killed near its ceiling would come back with a full budget every
// time.
//
// started is the run event's time pushed forward by however long the run sat on an
// unanswered checkpoint, so it is where the clock reads from rather than when the
// run opened.
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
  now = Date.now,
  seed: Seed = FRESH,
  prices: Prices = noPrices,
): Budget {
  return new Pool(limits, quota, now, seed, prices);
}

class Pool implements Budget {
  private calls: number;
  private cost: number;
  private tokens: TokenCounts;
  private readonly started: number;

  constructor(
    readonly limits: BudgetLimits,
    private readonly quota: Quota,
    private readonly now: () => number,
    seed: Seed,
    private readonly prices: Prices,
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

  // Rates from the backend catalog, applied to tokens this layer already has. The
  // catalog is not copied here: one repricing and a second table would disagree with
  // the dashboard about what a run cost.
  //
  // Never throws, and null rather than zero when nothing answered -- an unpriced call
  // must not read as a free one, either on the ledger or against the ceiling.
  async priceOf(modelId: string, providerType: string, tokens: TokenCounts): Promise<Priced> {
    const rates = await this.prices(modelId, providerType);
    return rates === null ? { cost_usd: null, source: null } : { cost_usd: costOf(rates, tokens), source: rates.source };
  }

  // An unreadable quota is not a refusal, but it is not a licence either: the local
  // total is held against max_cost_usd whether or not the gateway answers. That is
  // the arm every deployment takes, because unmeteredQuota is what harness.ts wires
  // -- so without it max_cost_usd would be a number a config can set and nothing
  // enforces, which is what it was.
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
}
