-- Seed for model_rates: the rates both languages read (GH #593)
--
-- Generated from core/llm/providers/registry.py's _CATALOG and
-- _CACHE_MULTIPLIERS as of this commit, then committed. It is not regenerated:
-- the catalog's rate fields are deleted in the same change, because this table
-- is now the single source and a second copy is the drift #593 was filed for.
--
-- model_id is the gateway's own prefixed form (provider/model), the string the
-- agent layer configures and Bifrost reports cost against. provider_type is
-- therefore redundant in the key and kept for the join to Python, which holds
-- the two separately.
--
-- Cache rates are stored, not derived. They were computed once here from the
-- per-provider multipliers the registry used to apply on every lookup:
--   anthropic: cache read 0.1x input, cache write 1.25x input
--   ollama: cache read 0.0x input, cache write 0.0x input
--   openai: cache read 0.5x input, cache write 0.0x input
--
-- A wildcard row prices a provider whose models are not enumerable. It is only
-- ever honoured for pricing_source = 'zero', so a wildcard can never make a
-- model that should have cost something look free.
--
-- Changing a rate ships as the NEXT numbered file. The Helm db-init Job records
-- applied filenames in _vigil_schema_versions and skips a file it has already
-- run, so editing this one would never reach an existing deployment.
--
-- Idempotent.

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
