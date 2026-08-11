-- One model rate table read by both languages, so pricing cannot drift.
-- Every rate is USD per MILLION tokens, here and everywhere.

CREATE TABLE IF NOT EXISTS model_rates (
    model_id             text          NOT NULL,
    provider_type        text          NOT NULL,
    input_per_mtok       numeric(12,6) NOT NULL,
    output_per_mtok      numeric(12,6) NOT NULL,
    cache_read_per_mtok  numeric(12,6) NOT NULL,
    cache_write_per_mtok numeric(12,6) NOT NULL,
    pricing_source       text          NOT NULL
        CHECK (pricing_source IN ('exact', 'heuristic', 'zero', 'unknown')),
    updated_at           timestamptz   NOT NULL DEFAULT now(),
    PRIMARY KEY (model_id, provider_type)
);

COMMENT ON TABLE model_rates IS
    'Model pricing read by both languages; a missing row is a refusal, never a zero.';

COMMENT ON COLUMN model_rates.pricing_source IS
    'exact from a price list, heuristic from a family guess, or zero for a free model.';
