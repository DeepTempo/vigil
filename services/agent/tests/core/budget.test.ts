import { describe, expect, it } from "vitest";
import { addTokens, budgetOf, unmeteredQuota } from "../../core/budget.js";
import type { Quota, SpendPayload, TokenCounts } from "../../contracts/budget.js";

function tokens(counts: Partial<TokenCounts>): TokenCounts {
  return { input: 0, output: 0, cache_read: 0, cache_write: 0, ...counts };
}

function reporting(used_usd: number, limit_usd: number): Quota {
  return { spent: async () => ({ used_usd, limit_usd }) };
}

function spend(counts: Partial<TokenCounts>, cost_usd: number | null = null): SpendPayload {
  return { model_id: "openai/gpt-4o", provider_type: "openai", role: "lead", tokens: tokens(counts), cost_usd };
}

function pool(quota: Quota, max_iterations = 100, max_cost_usd = 25) {
  return budgetOf({ max_iterations, max_cost_usd }, quota, "openai");
}

describe("iterations are the harness's to count", () => {
  it("advances only on beginIteration", async () => {
    const budget = pool(unmeteredQuota);
    expect(budget.spent.iterations).toBe(0);
    await budget.beginIteration();
    await budget.beginIteration();
    expect(budget.spent.iterations).toBe(2);
  });

  it("refuses once the cap is reached, without consuming another", async () => {
    const budget = pool(unmeteredQuota, 1);
    expect(await budget.beginIteration()).toBeNull();
    expect(await budget.beginIteration()).toEqual({ reason: "iterations_exhausted", used: 1, limit: 1 });
    expect(budget.spent.iterations).toBe(1);
  });
});

describe("dollars are the gateway's to enforce", () => {
  it("parks before paying for an iteration the gateway has no room for", async () => {
    const budget = pool(reporting(25, 25));
    expect(await budget.beginIteration()).toEqual({ reason: "cost_exhausted", used_usd: 25, limit_usd: 25 });
    expect(budget.spent.iterations).toBe(0);
  });

  it("takes the lower of the run's ceiling and the gateway's", async () => {
    const budget = pool(reporting(11, 500), 100, 10);
    expect(await budget.beginIteration()).toEqual({ reason: "cost_exhausted", used_usd: 11, limit_usd: 10 });
  });

  it("reports the gateway's number as spend rather than a local sum", async () => {
    const budget = pool(reporting(7.5, 25));
    await budget.beginIteration();
    budget.record(spend({ input: 100 }, 999));
    expect(budget.spent.cost_usd).toBe(7.5 + 999);
    await budget.beginIteration();
    expect(budget.spent.cost_usd).toBe(7.5);
  });

  // A gateway blip must not stop a run: the gateway still caps on its own side,
  // so an unreadable quota costs the pre-flight courtesy and nothing else.
  it("proceeds when the quota cannot be read", async () => {
    const budget = pool({ spent: async () => null });
    expect(await budget.beginIteration()).toBeNull();
  });
});

describe("tokens are journaled exactly", () => {
  it("accumulates every counter", () => {
    const budget = pool(unmeteredQuota);
    budget.record(spend({ input: 10, output: 2, cache_read: 3, cache_write: 4 }));
    budget.record(spend({ input: 5, output: 1 }));
    expect(budget.spent.tokens).toEqual({ input: 15, output: 3, cache_read: 3, cache_write: 4 });
  });

  it("journals tokens even when the gateway reported no cost", () => {
    const budget = pool(unmeteredQuota);
    budget.record(spend({ input: 42 }, null));
    expect(budget.spent.tokens.input).toBe(42);
    expect(budget.spent.cost_usd).toBe(0);
  });

  it("addTokens sums each counter independently", () => {
    expect(addTokens(tokens({ input: 1, cache_read: 2 }), tokens({ input: 3, cache_write: 4 }))).toEqual({
      input: 4,
      output: 0,
      cache_read: 2,
      cache_write: 4,
    });
  });
});
