import type { Pool } from "pg";
import { rateTableOf, type ModelRate, type PricingSource, type RateTable } from "../contracts/rates.js";

const SELECT =
  "SELECT model_id, provider_type, input_per_mtok, output_per_mtok, cache_read_per_mtok, cache_write_per_mtok, pricing_source FROM model_rates";

export class RatesUnavailable extends Error {}

// Read once at startup and frozen: the gate prices in-loop, and a run overshooting
// by one expensive iteration is what it exists to prevent. Rate changes ship as DDL.
export async function loadRates(pool: Pool): Promise<RateTable> {
  const result = await pool.query(SELECT).catch((error: unknown) => {
    // No partial table. A wrong rate does not mis-report, it disables the cap, so
    // refusing to start is the fail-closed answer.
    throw new RatesUnavailable(`model_rates could not be read: ${messageOf(error)}`);
  });
  if (result.rows.length === 0) throw new RatesUnavailable("model_rates is empty; nothing can be priced");
  return rateTableOf(result.rows.map(rowToRate));
}

function rowToRate(row: Record<string, unknown>): ModelRate {
  return {
    model_id: String(row["model_id"]),
    provider_type: String(row["provider_type"]),
    input_per_mtok: Number(row["input_per_mtok"]),
    output_per_mtok: Number(row["output_per_mtok"]),
    cache_read_per_mtok: Number(row["cache_read_per_mtok"]),
    cache_write_per_mtok: Number(row["cache_write_per_mtok"]),
    pricing_source: row["pricing_source"] as PricingSource,
  };
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
