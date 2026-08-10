import {
  ZERO_TOKENS,
  type Budget,
  type BudgetLimits,
  type Refusal,
  type Reservation,
  type ReserveOutcome,
  type Spend,
  type SpendPayload,
  type TokenCounts,
} from "../contracts/budget.js";
import type { ModelRate, RateTable } from "../contracts/rates.js";

const MILLION = 1_000_000;

export function addTokens(left: TokenCounts, right: TokenCounts): TokenCounts {
  return {
    input: left.input + right.input,
    output: left.output + right.output,
    cache_read: left.cache_read + right.cache_read,
    cache_write: left.cache_write + right.cache_write,
  };
}

// Every rate is USD per million tokens (#589 contract 5). cache_read is the
// cached share of input rather than an addition to it, so it is deducted from
// what input is billed at and charged at the cache rate instead. cache_write is
// assumed to sit outside input, which is the one part of the gateway's
// normalisation not confirmed by measurement -- #593 owns correcting it, and it
// is arithmetic in one place so that correction is one edit.
export function priceOf(rate: ModelRate, tokens: TokenCounts): number {
  const uncached = Math.max(0, tokens.input - tokens.cache_read);
  const perMillion =
    uncached * rate.input_per_mtok + tokens.output * rate.output_per_mtok +
    tokens.cache_read * rate.cache_read_per_mtok + tokens.cache_write * rate.cache_write_per_mtok;
  return perMillion / MILLION;
}

// The Budget contract plus the pricing the harness needs from it. Pricing lives
// with the budget because a caller pricing its own spend could disagree with the
// pool about what a call cost, and that is how a cap stops holding.
export interface PricingBudget extends Budget {
  price(model_id: string, role: string, tokens: TokenCounts, reservation: Reservation | null): SpendPayload | null;
}

// One pool, drawn on by every role in a run. Provider is bound at construction
// because reserve() carries only a model id, and one run speaks to one gateway.
export function budgetOf(limits: BudgetLimits, rates: RateTable, providerType: string): PricingBudget {
  return new Pool(limits, rates, providerType);
}

class Pool implements PricingBudget {
  private readonly outstanding = new Map<string, number>();
  private iterations = 0;
  private cost = 0;
  private tokens: TokenCounts = ZERO_TOKENS;
  private issued = 0;

  constructor(
    readonly limits: BudgetLimits,
    private readonly rates: RateTable,
    private readonly providerType: string,
  ) {}

  get spent(): Spend {
    return { iterations: this.iterations, cost_usd: this.cost, tokens: { ...this.tokens } };
  }

  beginIteration(): Refusal | null {
    const limit = this.limits.max_iterations;
    if (this.iterations >= limit) return { reason: "iterations_exhausted", used: this.iterations, limit };
    this.iterations += 1;
    return null;
  }

  reserve(model_id: string, estimate_tokens: TokenCounts): ReserveOutcome {
    const rate = this.rates.lookup(model_id, this.providerType);
    // Fails closed: a model with no rate is refused rather than priced at zero,
    // because a zero rate silently disables the cost cap entirely.
    if (rate === undefined) return { ok: false, refusal: { reason: "unpriced_model", model_id } };

    const limit_usd = this.limits.max_cost_usd;
    if (this.cost >= limit_usd) return { ok: false, refusal: { reason: "cost_exhausted", used_usd: this.cost, limit_usd } };

    // Outstanding reservations count against the pool, which is the whole reason
    // this is reserve/commit: concurrent independent checks each pass.
    const estimate_usd = priceOf(rate, estimate_tokens);
    const remaining_usd = limit_usd - this.cost - this.held();
    if (estimate_usd > remaining_usd) return { ok: false, refusal: { reason: "would_exceed", estimate_usd, remaining_usd } };

    const id = `rsv-${(this.issued += 1)}`;
    this.outstanding.set(id, estimate_usd);
    return { ok: true, reservation: { id, estimate_usd } };
  }

  commit(reservation: Reservation, actual: SpendPayload): void {
    this.outstanding.delete(reservation.id);
    this.cost += actual.cost_usd;
    this.tokens = addTokens(this.tokens, actual.tokens);
  }

  release(reservation: Reservation): void {
    this.outstanding.delete(reservation.id);
  }

  price(
    model_id: string,
    role: string,
    tokens: TokenCounts,
    reservation: Reservation | null,
  ): SpendPayload | null {
    const rate = this.rates.lookup(model_id, this.providerType);
    if (rate === undefined) return null;
    return {
      model_id,
      provider_type: this.providerType,
      role,
      tokens,
      cost_usd: priceOf(rate, tokens),
      pricing_source: rate.pricing_source,
      reservation_id: reservation === null ? null : reservation.id,
    };
  }

  private held(): number {
    return [...this.outstanding.values()].reduce((sum, estimate) => sum + estimate, 0);
  }
}
