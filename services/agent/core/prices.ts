import type { TokenCounts } from "../contracts/budget.js";

// What a model costs, per token, in USD. Four rates rather than two because cache
// tokens are not billed at the input rate -- counting a cache read at full price
// over-bills it tenfold on Anthropic, which is most of this deployment's traffic.
export interface Rates {
  input: number;
  output: number;
  cache_read: number;
  cache_write: number;
  // How the rates resolved: "exact" from a catalog entry, "heuristic" from a model-id
  // prefix, "zero" for self-hosted, "unknown" when nothing matched. A $0 call priced
  // from a real entry and a $0 call nobody could price look identical otherwise.
  source: string;
}

// Where a price comes from. A port because pricing is the backend's catalog and this
// layer must not hold a second copy of it: one repricing and the two would disagree
// about what a run cost.
export type Prices = (modelId: string, providerType: string) => Promise<Rates | null>;

// Nobody to ask, so nothing is priced and cost_usd stays null. For tests, and for a
// deployment running the agent without the backend reachable -- the run still runs
// and its token counts are still journaled, which is what the ledger is for.
export const noPrices: Prices = async () => null;

export function costOf(rates: Rates, tokens: TokenCounts): number {
  return (
    tokens.input * rates.input +
    tokens.output * rates.output +
    tokens.cache_read * rates.cache_read +
    tokens.cache_write * rates.cache_write
  );
}

export interface PricesOptions {
  url: string;
  token: string;
  fetch?: typeof globalThis.fetch;
}

// Memoised per model, because rates do not change while a process lives and this is
// asked once per model call. Only successes are remembered: a cached failure would
// disable pricing for the life of the worker over one blip.
//
// Never throws. A spend event that could not be priced is still a spend event, and
// losing it to a pricing outage would be strictly worse than not knowing the dollars.
export function httpPrices(options: PricesOptions): Prices {
  const call = options.fetch ?? globalThis.fetch;
  const base = options.url.replace(/\/$/, "");
  const known = new Map<string, Rates>();

  return async (modelId, providerType) => {
    const key = `${providerType}/${modelId}`;
    const held = known.get(key);
    if (held !== undefined) return held;

    const query = new URLSearchParams({ model_id: modelId, provider_type: providerType });
    try {
      const response = await call(`${base}/rates?${query.toString()}`, {
        headers: { "content-type": "application/json", authorization: `Bearer ${options.token}` },
      });
      if (!response.ok) return null;
      const rates = ratesOf(await response.json());
      if (rates !== null) known.set(key, rates);
      return rates;
    } catch {
      return null;
    }
  };
}

// A malformed answer prices nothing rather than pricing wrongly: a missing rate read
// as zero would silently under-bill every call for that model.
export function ratesOf(body: unknown): Rates | null {
  const raw = body as Record<string, unknown> | null;
  if (raw === null || typeof raw !== "object") return null;

  const rate = (field: string): number | null => {
    const value = raw[field];
    return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
  };

  const input = rate("input");
  const output = rate("output");
  const cache_read = rate("cache_read");
  const cache_write = rate("cache_write");
  if (input === null || output === null || cache_read === null || cache_write === null) return null;

  return {
    input,
    output,
    cache_read,
    cache_write,
    source: typeof raw["source"] === "string" ? raw["source"] : "unknown",
  };
}
