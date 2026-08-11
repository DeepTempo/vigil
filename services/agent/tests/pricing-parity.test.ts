import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { priceOf } from "../core/budget.js";
import { rateTableOf, type ModelRate, type PricingSource } from "../contracts/rates.js";
import type { TokenCounts } from "../contracts/budget.js";

// The other half of tests/unit/llm/test_pricing_parity.py. The fixture states
// expected_usd itself, hand-computed from the committed seed, so neither language
// is the oracle: a formula changed in one and not the other fails one of the two
// suites. The rates were the visible drift, but the formula was drifting too --
// Python billed input excluding the cached share, this layer billed it including
// -- and a rate-parity check alone would not have caught that (GH #593).
const ROOT = join(import.meta.dirname, "..", "..", "..");
const FIXTURE = join(ROOT, "tests", "fixtures", "pricing_parity.json");
const SEED = join(ROOT, "infra", "database", "init", "21_model_rates_seed.sql");

interface Case {
  name: string;
  model_id: string;
  provider_type: string;
  tokens: TokenCounts;
  expected_usd: number;
}

// Parsed rather than restated, for the same reason the Python fixture parses it:
// a rate mistyped in the SQL has to fail a price assertion, not sail through
// because the test carries its own copy.
const VALUES = /VALUES \('([^']+)', '([^']+)', ([\d.]+), ([\d.]+), ([\d.]+), ([\d.]+), '([^']+)'\)/g;

function seededRates(): ModelRate[] {
  const rates = [...readFileSync(SEED, "utf8").matchAll(VALUES)].map((match): ModelRate => ({
    model_id: match[1]!,
    provider_type: match[2]!,
    input_per_mtok: Number(match[3]),
    output_per_mtok: Number(match[4]),
    cache_read_per_mtok: Number(match[5]),
    cache_write_per_mtok: Number(match[6]),
    pricing_source: match[7] as PricingSource,
  }));
  expect(rates.length).toBeGreaterThan(0);
  return rates;
}

const table = rateTableOf(seededRates());
const cases: Case[] = (JSON.parse(readFileSync(FIXTURE, "utf8")) as { cases: Case[] }).cases;

describe("pricing agrees with the other language", () => {
  it.each(cases.map((one) => [one.name, one] as const))("%s", (_name, one) => {
    const rate = table.lookup(one.model_id, one.provider_type);
    expect(rate, `${one.model_id} is not priced by the seed`).toBeDefined();
    expect(priceOf(rate!, one.tokens)).toBeCloseTo(one.expected_usd, 12);
  });

  // A fixture of only uncached calls would pass whatever the formula did with
  // the cached share, which is the exact thing being pinned.
  it("covers both cache directions", () => {
    expect(cases.some((one) => one.tokens.cache_read > 0)).toBe(true);
    expect(cases.some((one) => one.tokens.cache_write > 0)).toBe(true);
  });
});
