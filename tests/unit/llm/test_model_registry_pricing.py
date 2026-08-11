"""Tests for the model registry's pricing helpers.

Rates come from the committed seed via the ``seeded_rates`` fixture, so a rate
mistyped in the SQL fails here rather than shipping.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO))

pytestmark = pytest.mark.unit


def test_cache_rates_come_from_the_table_not_a_multiplier(seeded_rates):
    """Stored, not derived: the agent layer prices the same calls, so a
    multiplier here would have had to be reimplemented there to agree."""
    from core.llm.providers.registry import get_registry

    registry = get_registry()
    read, write = registry.get_cache_rates("claude-sonnet-4-5-20250929", "anthropic")
    assert read == pytest.approx(0.30 / 1_000_000)
    assert write == pytest.approx(3.75 / 1_000_000)


def test_openai_charges_nothing_extra_for_a_cache_write(seeded_rates):
    """The gateway's prompt_tokens already covers an OpenAI cache write, so the
    stored rate is zero rather than a premium."""
    from core.llm.providers.registry import get_registry

    read, write = get_registry().get_cache_rates("gpt-4o", "openai")
    assert read == pytest.approx(1.25 / 1_000_000)
    assert write == 0.0


def test_an_unpriced_model_charges_cache_at_the_full_input_rate(seeded_rates):
    """A tier heuristic has no stored cache rates, so cache tokens charge at the
    full input rate: the right direction when the real rate is unknown."""
    from core.llm.providers.registry import get_registry

    registry = get_registry()
    in_rate, _ = registry.get_cost_rates("claude-sonnet-9-future", "anthropic")
    read, write = registry.get_cache_rates("claude-sonnet-9-future", "anthropic")
    assert in_rate > 0
    assert read == pytest.approx(in_rate)
    assert write == pytest.approx(in_rate)


def test_a_self_hosted_model_is_priced_by_the_wildcard_row(seeded_rates):
    """Ollama models cannot be enumerated, so one wildcard row prices them all."""
    from core.llm.providers.registry import get_registry

    registry = get_registry()
    assert registry.get_cost_rates("some-local-llama", "ollama") == (0.0, 0.0)
    assert registry.get_pricing_source("some-local-llama", "ollama") == "zero"


def test_a_wildcard_never_prices_a_model_that_should_have_cost_something(seeded_rates):
    """A zero-cost mechanism, not a general fallback: honouring one at a non-zero
    source would let a whole provider be mispriced by a single row."""
    from core.llm.cost import rates as rate_table

    rate_table.load_rates(
        [
            rate_table.ModelRate(
                model_id="*",
                provider_type="expensive",
                input_per_mtok=999.0,
                output_per_mtok=999.0,
                cache_read_per_mtok=999.0,
                cache_write_per_mtok=999.0,
                pricing_source="exact",
            )
        ]
    )
    assert rate_table.lookup("expensive", "anything") is None


def test_the_table_is_read_once(seeded_rates, monkeypatch):
    """Pricing is on the hot path for every call, so a per-call query is not an
    option. Read once, frozen, and re-read only on restart."""
    from core.llm.cost import rates as rate_table

    rate_table.reset_rates()
    reads = {"n": 0}

    def counting_read():
        reads["n"] += 1
        return {}

    monkeypatch.setattr(rate_table, "_read", counting_read)
    rate_table.lookup("anthropic", "claude-sonnet-4-6")
    rate_table.lookup("openai", "gpt-4o")
    assert reads["n"] == 1


def test_pricing_source_exact_for_catalog_models(seeded_rates):
    from core.llm.providers.registry import get_registry

    src = get_registry().get_pricing_source("claude-sonnet-4-5-20250929", "anthropic")
    assert src == "exact"


def test_pricing_source_heuristic_for_unknown_anthropic_variant(seeded_rates):
    """A model id we haven't catalog'd but matches a tier regex (e.g.
    a future Sonnet variant) should resolve via heuristic."""
    from core.llm.providers.registry import get_registry

    src = get_registry().get_pricing_source("claude-sonnet-9-99-future", "anthropic")
    assert src == "heuristic"


def test_pricing_source_zero_for_ollama(seeded_rates):
    from core.llm.providers.registry import get_registry

    assert get_registry().get_pricing_source("llama3.1", "ollama") == "zero"


def test_pricing_source_unknown_for_novel_provider(seeded_rates):
    from core.llm.providers.registry import get_registry

    assert get_registry().get_pricing_source("foo-1", "future-vendor") == "unknown"


def test_unknown_pricing_increments_counter(seeded_rates, monkeypatch):
    """#184 acceptance #2: the 'unknown' path must increment the OTEL
    counter so dashboards/alerts can see unsupported models, not silently
    record $0."""
    from core.llm.providers import registry as model_registry

    calls = []
    monkeypatch.setattr(
        model_registry,
        "_record_pricing_unknown",
        lambda provider_type, model_id: calls.append((provider_type, model_id)),
    )
    # Trigger the unknown branch via the public API.
    src = model_registry.get_registry().get_pricing_source("foo-1", "future-vendor")
    assert src == "unknown"
    assert ("future-vendor", "foo-1") in calls


def test_known_pricing_does_not_increment_counter(seeded_rates, monkeypatch):
    """Known models must NOT increment the unknown-pricing counter."""
    from core.llm.providers import registry as model_registry

    calls = []
    monkeypatch.setattr(
        model_registry,
        "_record_pricing_unknown",
        lambda provider_type, model_id: calls.append((provider_type, model_id)),
    )
    # claude-sonnet-4-5-20250929 should resolve to "exact" via _CATALOG.
    src = model_registry.get_registry().get_pricing_source(
        "claude-sonnet-4-5-20250929", "anthropic"
    )
    assert src in ("exact", "heuristic")
    assert calls == []


def test_infer_provider_type_anthropic():
    from core.llm.providers.registry import infer_provider_type

    assert infer_provider_type("claude-sonnet-4-5-20250929") == "anthropic"
    assert infer_provider_type("claude-opus-4-7") == "anthropic"


def test_infer_provider_type_openai():
    from core.llm.providers.registry import infer_provider_type

    assert infer_provider_type("gpt-4o") == "openai"
    assert infer_provider_type("gpt-4o-mini") == "openai"
    assert infer_provider_type("o1-mini") == "openai"
    assert infer_provider_type("o3") == "openai"


def test_infer_provider_type_ollama_soft_match():
    from core.llm.providers.registry import infer_provider_type

    assert infer_provider_type("llama3.1") == "ollama"
    assert infer_provider_type("mistral-7b") == "ollama"
    assert infer_provider_type("qwen2.5") == "ollama"


def test_infer_provider_type_unknown():
    from core.llm.providers.registry import infer_provider_type

    assert infer_provider_type("") == "unknown"
    assert infer_provider_type("some-novel-thing") == "unknown"
