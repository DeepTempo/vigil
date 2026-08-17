import { describe, expect, it } from "vitest";
import { costOf, httpPrices, ratesOf } from "../../core/prices.js";

const RATES = { input: 3e-6, output: 1.5e-5, cache_read: 3e-7, cache_write: 3.75e-6 };

function answering(body: unknown, seen: string[] = []): typeof globalThis.fetch {
  return (async (url: string) => {
    seen.push(String(url));
    return { ok: true, json: async () => body } as Response;
  }) as unknown as typeof globalThis.fetch;
}

// The catalog answers four zeros for a model nothing matched, which parse as
// perfectly good rates. Reading them as a price is how a run spends unmetered.
describe("what the catalog could not price", () => {
  it("prices nothing when the source is unknown", () => {
    expect(ratesOf({ input: 0, output: 0, cache_read: 0, cache_write: 0, source: "unknown" })).toBeNull();
  });

  it("still prices a model that genuinely costs nothing", () => {
    const rates = ratesOf({ input: 0, output: 0, cache_read: 0, cache_write: 0, source: "zero" });
    expect(rates?.source).toBe("zero");
    expect(costOf(rates!, { input: 1000, output: 1000, cache_read: 0, cache_write: 0 })).toBe(0);
  });

  it("prices nothing when a rate is missing rather than reading it as free", () => {
    expect(ratesOf({ input: 3e-6, output: 1.5e-5, cache_read: 3e-7, source: "exact" })).toBeNull();
  });
});

describe("asking the catalog", () => {
  it("keeps a price it was given and asks once", async () => {
    const seen: string[] = [];
    const prices = httpPrices({ url: "http://backend/internal/pricing", token: "t", fetch: answering({ ...RATES, source: "exact" }, seen) });
    expect(await prices("claude-sonnet-4-6", "bifrost")).not.toBeNull();
    expect(await prices("claude-sonnet-4-6", "bifrost")).not.toBeNull();
    expect(seen).toHaveLength(1);
  });

  // Kept out of the memo deliberately: the run refuses after UNPRICED_TOLERANCE,
  // and a cached null would outlive a catalog that has since been given the model.
  it("asks again after an answer that priced nothing", async () => {
    const seen: string[] = [];
    const prices = httpPrices({ url: "http://backend/internal/pricing", token: "t", fetch: answering({ ...RATES, input: 0, output: 0, cache_read: 0, cache_write: 0, source: "unknown" }, seen) });
    expect(await prices("nobody-knows", "bifrost")).toBeNull();
    expect(await prices("nobody-knows", "bifrost")).toBeNull();
    expect(seen).toHaveLength(2);
  });
});
