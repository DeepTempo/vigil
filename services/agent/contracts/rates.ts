// One of the five Phase-0 contracts, consumed by the budget gate, which prices
// in-loop against it rather than paying a per-call gateway round-trip.

export const PRICING_SOURCES = ["exact", "heuristic", "zero", "unknown"] as const;
export type PricingSource = (typeof PRICING_SOURCES)[number];

// Rates are USD per million tokens, here and everywhere. The Python registry
// stores per-million and hands out per-1k, which is the drift this table ends.
export interface ModelRate {
  model_id: string;
  provider_type: string;
  input_per_mtok: number;
  output_per_mtok: number;
  cache_read_per_mtok: number;
  cache_write_per_mtok: number;
  pricing_source: PricingSource;
}

// Read once at startup and frozen: gating cannot afford a per-call round-trip.
// A miss returns undefined so the budget refuses, rather than pricing at zero.
export interface RateTable {
  lookup(model_id: string, provider_type: string): ModelRate | undefined;
  readonly size: number;
}

// Stands in for a provider whose models cannot be enumerated -- self-hosted
// Ollama being the case that exists, priced at zero and named freely.
export const WILDCARD = "*";

export class RateTableError extends Error {}

// model_id is the gateway's own prefixed provider/model, so it is the whole key:
// the prefix is the provider, and two providers cannot share one id.
export function rateTableOf(rates: readonly ModelRate[]): RateTable {
  const byModel = new Map<string, ModelRate>();
  for (const rate of rates) {
    // An id not carrying its own provider breaks the key's assumption. A rate
    // table this layer cannot trust stops the run rather than pricing against it.
    if (!rate.model_id.startsWith(`${rate.provider_type}/`)) {
      throw new RateTableError(`rate ${rate.model_id} is not prefixed with its provider ${rate.provider_type}`);
    }
    byModel.set(rate.model_id, rate);
  }
  return { lookup: (model, provider) => lookupIn(byModel, model, provider), size: byModel.size };
}

// Provider stays load-bearing though the prefix carries it: a caller that
// disagrees with itself gets a miss, and so a refusal, rather than a price.
function lookupIn(byModel: ReadonlyMap<string, ModelRate>, model: string, provider: string): ModelRate | undefined {
  const found = byModel.get(model);
  if (found !== undefined) return found.provider_type === provider ? found : undefined;
  return wildcard(byModel, provider);
}

// Honoured only at pricing_source zero, so one row can never make a provider's
// priced models look free.
function wildcard(byModel: ReadonlyMap<string, ModelRate>, provider: string): ModelRate | undefined {
  const found = byModel.get(`${provider}/${WILDCARD}`);
  return found?.pricing_source === "zero" ? found : undefined;
}
