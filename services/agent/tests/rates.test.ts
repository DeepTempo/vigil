import { afterAll, beforeAll, describe, expect, it } from "vitest";
import pg from "pg";
import { loadRates, RatesUnavailable } from "../rates/repository.js";
import { rateTableOf, RateTableError, WILDCARD } from "../contracts/rates.js";
import { budgetOf } from "../core/budget.js";

const url = process.env["DATABASE_URL"];
const pool = new pg.Pool({ connectionString: url });

beforeAll(async () => {
  // The seed is applied by the same CI step that applies the DDL, so the rows
  // under test are the committed ones rather than a copy made here.
  const count = await pool.query<{ count: string }>("SELECT count(*) AS count FROM model_rates");
  expect(Number(count.rows[0]!.count)).toBeGreaterThan(0);
});

afterAll(async () => {
  await pool.end();
});

describe("loading the rate table", () => {
  it("reads the seeded rows and prices a model from them", async () => {
    const table = await loadRates(pool);
    expect(table.size).toBeGreaterThan(1);

    const sonnet = table.lookup("anthropic/claude-sonnet-4-6", "anthropic");
    expect(sonnet).toMatchObject({
      input_per_mtok: 3,
      output_per_mtok: 15,
      cache_read_per_mtok: 0.3,
      cache_write_per_mtok: 3.75,
      pricing_source: "exact",
    });
  });

  // The whole reason the table exists rather than a config file: numeric(12,6)
  // arrives from pg as a string, and Number() on it is the one place that matters.
  it("reads a rate as a number, not as the string Postgres sends", async () => {
    const table = await loadRates(pool);
    const rate = table.lookup("openai/gpt-4o", "openai");
    expect(typeof rate?.input_per_mtok).toBe("number");
    expect(rate?.input_per_mtok).toBe(2.5);
  });

  it("prices a self-hosted model nobody enumerated, through the wildcard", async () => {
    const table = await loadRates(pool);
    const local = table.lookup("ollama/whatever-was-pulled-today", "ollama");
    expect(local?.pricing_source).toBe("zero");
    expect(local?.input_per_mtok).toBe(0);
  });

  it("does not let the wildcard price a provider it was not written for", async () => {
    const table = await loadRates(pool);
    expect(table.lookup("openai/gpt-5-unreleased", "openai")).toBeUndefined();
  });

  // The budget refuses rather than pricing at zero, which is what makes an
  // unseeded model a stopped run instead of a silently uncapped one.
  it("leaves an unpriced model refusable by the budget", async () => {
    const table = await loadRates(pool);
    const budget = budgetOf({ max_iterations: 10, max_cost_usd: 100 }, table, "openai");
    const outcome = budget.reserve("openai/gpt-5-unreleased", {
      input: 1_000,
      output: 100,
      cache_read: 0,
      cache_write: 0,
    });
    expect(outcome).toEqual({
      ok: false,
      refusal: { reason: "unpriced_model", model_id: "openai/gpt-5-unreleased" },
    });
  });

  it("refuses to start rather than price against a table it cannot read", async () => {
    const broken = new pg.Pool({ connectionString: "postgres://nobody@127.0.0.1:1/none" });
    await expect(loadRates(broken)).rejects.toThrow(RatesUnavailable);
    await broken.end();
  });
});

describe("the table's key", () => {
  const row = {
    provider_type: "openai",
    input_per_mtok: 1,
    output_per_mtok: 1,
    cache_read_per_mtok: 0,
    cache_write_per_mtok: 0,
    pricing_source: "exact" as const,
  };

  // model_id is the whole key, so a row whose id does not carry its own provider
  // would be reachable under a provider it does not belong to.
  it("refuses a row whose id is not prefixed with its provider", () => {
    expect(() => rateTableOf([{ ...row, model_id: "gpt-4o" }])).toThrow(RateTableError);
    expect(() => rateTableOf([{ ...row, model_id: "anthropic/claude-opus-5" }])).toThrow(RateTableError);
  });

  it("accepts a wildcard row, which carries its provider like any other", () => {
    const table = rateTableOf([{ ...row, model_id: `openai/${WILDCARD}`, pricing_source: "zero" }]);
    expect(table.lookup("openai/anything", "openai")?.pricing_source).toBe("zero");
  });
});
