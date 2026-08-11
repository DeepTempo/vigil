-- Seed for model_rates, generated once from the Python catalog and committed.
-- Changing a rate ships as the NEXT numbered file; db-init skips one it has run.

INSERT INTO model_rates (model_id, provider_type, input_per_mtok, output_per_mtok,
                         cache_read_per_mtok, cache_write_per_mtok, pricing_source)
VALUES ('anthropic/claude-3-5-haiku-20241022', 'anthropic', 0.800000, 4.000000, 0.080000, 1.000000, 'exact')
ON CONFLICT (model_id, provider_type) DO UPDATE SET
    input_per_mtok       = EXCLUDED.input_per_mtok,
    output_per_mtok      = EXCLUDED.output_per_mtok,
    cache_read_per_mtok  = EXCLUDED.cache_read_per_mtok,
    cache_write_per_mtok = EXCLUDED.cache_write_per_mtok,
    pricing_source       = EXCLUDED.pricing_source,
    updated_at           = now();

INSERT INTO model_rates (model_id, provider_type, input_per_mtok, output_per_mtok,
                         cache_read_per_mtok, cache_write_per_mtok, pricing_source)
VALUES ('anthropic/claude-3-5-sonnet-20241022', 'anthropic', 3.000000, 15.000000, 0.300000, 3.750000, 'exact')
ON CONFLICT (model_id, provider_type) DO UPDATE SET
    input_per_mtok       = EXCLUDED.input_per_mtok,
    output_per_mtok      = EXCLUDED.output_per_mtok,
    cache_read_per_mtok  = EXCLUDED.cache_read_per_mtok,
    cache_write_per_mtok = EXCLUDED.cache_write_per_mtok,
    pricing_source       = EXCLUDED.pricing_source,
    updated_at           = now();

INSERT INTO model_rates (model_id, provider_type, input_per_mtok, output_per_mtok,
                         cache_read_per_mtok, cache_write_per_mtok, pricing_source)
VALUES ('anthropic/claude-3-haiku-20240307', 'anthropic', 0.250000, 1.250000, 0.025000, 0.312500, 'exact')
ON CONFLICT (model_id, provider_type) DO UPDATE SET
    input_per_mtok       = EXCLUDED.input_per_mtok,
    output_per_mtok      = EXCLUDED.output_per_mtok,
    cache_read_per_mtok  = EXCLUDED.cache_read_per_mtok,
    cache_write_per_mtok = EXCLUDED.cache_write_per_mtok,
    pricing_source       = EXCLUDED.pricing_source,
    updated_at           = now();

INSERT INTO model_rates (model_id, provider_type, input_per_mtok, output_per_mtok,
                         cache_read_per_mtok, cache_write_per_mtok, pricing_source)
VALUES ('anthropic/claude-haiku-4-5-20251001', 'anthropic', 0.800000, 4.000000, 0.080000, 1.000000, 'exact')
ON CONFLICT (model_id, provider_type) DO UPDATE SET
    input_per_mtok       = EXCLUDED.input_per_mtok,
    output_per_mtok      = EXCLUDED.output_per_mtok,
    cache_read_per_mtok  = EXCLUDED.cache_read_per_mtok,
    cache_write_per_mtok = EXCLUDED.cache_write_per_mtok,
    pricing_source       = EXCLUDED.pricing_source,
    updated_at           = now();

INSERT INTO model_rates (model_id, provider_type, input_per_mtok, output_per_mtok,
                         cache_read_per_mtok, cache_write_per_mtok, pricing_source)
VALUES ('anthropic/claude-opus-4-20250514', 'anthropic', 15.000000, 75.000000, 1.500000, 18.750000, 'exact')
ON CONFLICT (model_id, provider_type) DO UPDATE SET
    input_per_mtok       = EXCLUDED.input_per_mtok,
    output_per_mtok      = EXCLUDED.output_per_mtok,
    cache_read_per_mtok  = EXCLUDED.cache_read_per_mtok,
    cache_write_per_mtok = EXCLUDED.cache_write_per_mtok,
    pricing_source       = EXCLUDED.pricing_source,
    updated_at           = now();

INSERT INTO model_rates (model_id, provider_type, input_per_mtok, output_per_mtok,
                         cache_read_per_mtok, cache_write_per_mtok, pricing_source)
VALUES ('anthropic/claude-opus-4-7', 'anthropic', 15.000000, 75.000000, 1.500000, 18.750000, 'exact')
ON CONFLICT (model_id, provider_type) DO UPDATE SET
    input_per_mtok       = EXCLUDED.input_per_mtok,
    output_per_mtok      = EXCLUDED.output_per_mtok,
    cache_read_per_mtok  = EXCLUDED.cache_read_per_mtok,
    cache_write_per_mtok = EXCLUDED.cache_write_per_mtok,
    pricing_source       = EXCLUDED.pricing_source,
    updated_at           = now();

INSERT INTO model_rates (model_id, provider_type, input_per_mtok, output_per_mtok,
                         cache_read_per_mtok, cache_write_per_mtok, pricing_source)
VALUES ('anthropic/claude-sonnet-4-20250514', 'anthropic', 3.000000, 15.000000, 0.300000, 3.750000, 'exact')
ON CONFLICT (model_id, provider_type) DO UPDATE SET
    input_per_mtok       = EXCLUDED.input_per_mtok,
    output_per_mtok      = EXCLUDED.output_per_mtok,
    cache_read_per_mtok  = EXCLUDED.cache_read_per_mtok,
    cache_write_per_mtok = EXCLUDED.cache_write_per_mtok,
    pricing_source       = EXCLUDED.pricing_source,
    updated_at           = now();

INSERT INTO model_rates (model_id, provider_type, input_per_mtok, output_per_mtok,
                         cache_read_per_mtok, cache_write_per_mtok, pricing_source)
VALUES ('anthropic/claude-sonnet-4-5-20250929', 'anthropic', 3.000000, 15.000000, 0.300000, 3.750000, 'exact')
ON CONFLICT (model_id, provider_type) DO UPDATE SET
    input_per_mtok       = EXCLUDED.input_per_mtok,
    output_per_mtok      = EXCLUDED.output_per_mtok,
    cache_read_per_mtok  = EXCLUDED.cache_read_per_mtok,
    cache_write_per_mtok = EXCLUDED.cache_write_per_mtok,
    pricing_source       = EXCLUDED.pricing_source,
    updated_at           = now();

INSERT INTO model_rates (model_id, provider_type, input_per_mtok, output_per_mtok,
                         cache_read_per_mtok, cache_write_per_mtok, pricing_source)
VALUES ('anthropic/claude-sonnet-4-6', 'anthropic', 3.000000, 15.000000, 0.300000, 3.750000, 'exact')
ON CONFLICT (model_id, provider_type) DO UPDATE SET
    input_per_mtok       = EXCLUDED.input_per_mtok,
    output_per_mtok      = EXCLUDED.output_per_mtok,
    cache_read_per_mtok  = EXCLUDED.cache_read_per_mtok,
    cache_write_per_mtok = EXCLUDED.cache_write_per_mtok,
    pricing_source       = EXCLUDED.pricing_source,
    updated_at           = now();

INSERT INTO model_rates (model_id, provider_type, input_per_mtok, output_per_mtok,
                         cache_read_per_mtok, cache_write_per_mtok, pricing_source)
VALUES ('openai/gpt-4-turbo', 'openai', 10.000000, 30.000000, 5.000000, 0.000000, 'exact')
ON CONFLICT (model_id, provider_type) DO UPDATE SET
    input_per_mtok       = EXCLUDED.input_per_mtok,
    output_per_mtok      = EXCLUDED.output_per_mtok,
    cache_read_per_mtok  = EXCLUDED.cache_read_per_mtok,
    cache_write_per_mtok = EXCLUDED.cache_write_per_mtok,
    pricing_source       = EXCLUDED.pricing_source,
    updated_at           = now();

INSERT INTO model_rates (model_id, provider_type, input_per_mtok, output_per_mtok,
                         cache_read_per_mtok, cache_write_per_mtok, pricing_source)
VALUES ('openai/gpt-4o', 'openai', 2.500000, 10.000000, 1.250000, 0.000000, 'exact')
ON CONFLICT (model_id, provider_type) DO UPDATE SET
    input_per_mtok       = EXCLUDED.input_per_mtok,
    output_per_mtok      = EXCLUDED.output_per_mtok,
    cache_read_per_mtok  = EXCLUDED.cache_read_per_mtok,
    cache_write_per_mtok = EXCLUDED.cache_write_per_mtok,
    pricing_source       = EXCLUDED.pricing_source,
    updated_at           = now();

INSERT INTO model_rates (model_id, provider_type, input_per_mtok, output_per_mtok,
                         cache_read_per_mtok, cache_write_per_mtok, pricing_source)
VALUES ('openai/gpt-4o-mini', 'openai', 0.150000, 0.600000, 0.075000, 0.000000, 'exact')
ON CONFLICT (model_id, provider_type) DO UPDATE SET
    input_per_mtok       = EXCLUDED.input_per_mtok,
    output_per_mtok      = EXCLUDED.output_per_mtok,
    cache_read_per_mtok  = EXCLUDED.cache_read_per_mtok,
    cache_write_per_mtok = EXCLUDED.cache_write_per_mtok,
    pricing_source       = EXCLUDED.pricing_source,
    updated_at           = now();

INSERT INTO model_rates (model_id, provider_type, input_per_mtok, output_per_mtok,
                         cache_read_per_mtok, cache_write_per_mtok, pricing_source)
VALUES ('ollama/*', 'ollama', 0.000000, 0.000000, 0.000000, 0.000000, 'zero')
ON CONFLICT (model_id, provider_type) DO UPDATE SET
    input_per_mtok       = EXCLUDED.input_per_mtok,
    output_per_mtok      = EXCLUDED.output_per_mtok,
    cache_read_per_mtok  = EXCLUDED.cache_read_per_mtok,
    cache_write_per_mtok = EXCLUDED.cache_write_per_mtok,
    pricing_source       = EXCLUDED.pricing_source,
    updated_at           = now();
