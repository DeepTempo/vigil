import { describe, expect, it } from "vitest";
import { budgetOf, priceOf } from "../../core/budget.js";
import { rateTableOf, type ModelRate } from "../../contracts/rates.js";
import type { TokenCounts } from "../../contracts/budget.js";

const RATE: ModelRate = {
  model_id: "gpt-4o",
  provider_type: "openai",
  input_per_mtok: 10,
  output_per_mtok: 30,
  cache_read_per_mtok: 1,
  cache_write_per_mtok: 12.5,
  pricing_source: "exact",
};

const RATES = rateTableOf([RATE]);

function tokens(counts: Partial<TokenCounts>): TokenCounts {
  return { input: 0, output: 0, cache_read: 0, cache_write: 0, ...counts };
}

function pool(max_cost_usd: number, max_iterations = 100) {
  return budgetOf({ max_iterations, max_cost_usd }, RATES, "openai");
}

describe("pricing", () => {
  // cache_read is the cached share of input, so it is deducted from what input
  // is billed at rather than charged twice.
  it("bills the cached share of input at the cache rate", () => {
    const priced = priceOf(RATE, tokens({ input: 1_000, cache_read: 800, output: 100 }));
    expect(priced).toBeCloseTo((200 * 10 + 800 * 1 + 100 * 30) / 1_000_000);
  });

  it("never bills a negative input when the cached share is reported larger", () => {
    expect(priceOf(RATE, tokens({ input: 100, cache_read: 500 }))).toBeCloseTo((500 * 1) / 1_000_000);
  });
});

describe("reserve", () => {
  // A zero rate silently disables the cost cap entirely, so a model with no row
  // in the table is refused instead.
  it("refuses an unpriced model rather than pricing it at zero", () => {
    const outcome = pool(1).reserve("claude-opus-5", tokens({ input: 1_000 }));
    expect(outcome).toEqual({ ok: false, refusal: { reason: "unpriced_model", model_id: "claude-opus-5" } });
  });

  it("issues a reservation priced from the table", () => {
    const outcome = pool(25).reserve("gpt-4o", tokens({ input: 1_000_000 }));
    expect(outcome.ok && outcome.reservation.estimate_usd).toBe(10);
  });

  // The reason the contract is reserve/commit rather than check/spend: two
  // independent checks against the same pool would each pass.
  it("counts an outstanding reservation against the pool", () => {
    const budget = pool(15);
    expect(budget.reserve("gpt-4o", tokens({ input: 1_000_000 })).ok).toBe(true);
    const second = budget.reserve("gpt-4o", tokens({ input: 1_000_000 }));
    expect(second.ok).toBe(false);
    expect(!second.ok && second.refusal).toEqual({ reason: "would_exceed", estimate_usd: 10, remaining_usd: 5 });
  });

  it("returns the pool when a reservation is released unspent", () => {
    const budget = pool(15);
    const first = budget.reserve("gpt-4o", tokens({ input: 1_000_000 }));
    if (!first.ok) throw new Error("the first reservation should have been issued");
    budget.release(first.reservation);
    expect(budget.reserve("gpt-4o", tokens({ input: 1_000_000 })).ok).toBe(true);
  });

  it("refuses once what was actually committed reaches the cap", () => {
    const budget = pool(10);
    const first = budget.reserve("gpt-4o", tokens({ input: 1_000_000 }));
    if (!first.ok) throw new Error("the first reservation should have been issued");

    const payload = budget.price("gpt-4o", "lead", tokens({ input: 1_000_000 }), first.reservation);
    if (payload === null) throw new Error("a model the table prices should price");
    budget.commit(first.reservation, payload);

    expect(budget.spent.cost_usd).toBe(10);
    const second = budget.reserve("gpt-4o", tokens({ input: 1 }));
    expect(!second.ok && second.refusal.reason).toBe("cost_exhausted");
  });
});

describe("iterations", () => {
  // Separate from reserve because a tool loop is many model calls inside one
  // iteration, so counting calls would exhaust the limit far too early.
  it("advances only on beginIteration", () => {
    const budget = pool(1_000, 2);
    expect(budget.beginIteration()).toBeNull();
    budget.reserve("gpt-4o", tokens({ input: 10 }));
    budget.reserve("gpt-4o", tokens({ input: 10 }));
    expect(budget.spent.iterations).toBe(1);
  });

  it("refuses once the iteration limit is reached", () => {
    const budget = pool(1_000, 2);
    expect(budget.beginIteration()).toBeNull();
    expect(budget.beginIteration()).toBeNull();
    expect(budget.beginIteration()).toEqual({ reason: "iterations_exhausted", used: 2, limit: 2 });
  });
});

describe("spend", () => {
  it("accumulates tokens across calls and carries the pricing source", () => {
    const budget = pool(1_000);
    for (const _ of [1, 2]) {
      const outcome = budget.reserve("gpt-4o", tokens({ input: 100 }));
      if (!outcome.ok) throw new Error("the reservation should have been issued");
      const payload = budget.price("gpt-4o", "lead", tokens({ input: 100, output: 20 }), outcome.reservation);
      if (payload === null) throw new Error("a model the table prices should price");
      expect(payload.pricing_source).toBe("exact");
      expect(payload.reservation_id).toBe(outcome.reservation.id);
      budget.commit(outcome.reservation, payload);
    }
    expect(budget.spent.tokens).toEqual(tokens({ input: 200, output: 40 }));
  });

  it("does not hand out the running total for a caller to edit", () => {
    const budget = pool(1_000);
    budget.spent.tokens.input = 9_999;
    expect(budget.spent.tokens.input).toBe(0);
  });
});
