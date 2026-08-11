import logging
from typing import Optional

from core.llm.cost.rates import MILLION, Rates, TokenCounts, price_tokens

logger = logging.getLogger(__name__)


def compute_call_cost(
    model_id: Optional[str],
    provider_type: Optional[str],
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int = 0,
    cache_creation_tokens: int = 0,
) -> float:
    """Compute USD cost of a single LLM call.

    Rates come from ``model_rates`` via the registry; cache rates are stored
    there rather than derived from a multiplier table. The arithmetic is
    ``core.llm.cost.rates.price_tokens``, which the agent layer's budget mirrors,
    so the same call costs the same in both languages.

    Cache tokens are billed at their own rates. Counting them at full input rate
    over-bills Anthropic cache reads by 10× and under-bills writes by 25%, so it
    matters for any workload using prompt caching — most of Vigil's traffic
    after #84 PR-C.

    GH #84 PR-E removed the previous Sonnet-pricing fallback: with
    per-component model selection (#89) active, silently billing a GPT-4o
    or Ollama call at Sonnet rates would misattribute cost. On an
    unresolved model/provider we return 0.0 and log at WARNING so the
    call surfaces as a visible zero on the ``/analytics/cost`` dashboard
    rather than hiding inside a misattributed bucket.
    """
    if not model_id or not provider_type:
        logger.warning(
            "compute_call_cost: missing model_id/provider_type (got %r / %r); "
            "recording cost as $0.00 (GH #84 PR-E)",
            model_id,
            provider_type,
        )
        return 0.0
    try:
        from core.llm.providers.registry import get_registry

        registry = get_registry()
        in_rate, out_rate = registry.get_cost_rates(model_id, provider_type)
        cache_read_rate, cache_write_rate = registry.get_cache_rates(
            model_id, provider_type
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "compute_call_cost: model_registry lookup failed for %s/%s (%s); "
            "recording cost as $0.00",
            provider_type,
            model_id,
            exc,
        )
        return 0.0

    # Arguments are Anthropic-native, where input_tokens excludes both cache shares.
    # They are added here to reach the shared shape, and price_tokens removes them.
    rates = Rates(
        input_per_mtok=in_rate * MILLION,
        output_per_mtok=out_rate * MILLION,
        cache_read_per_mtok=cache_read_rate * MILLION,
        cache_write_per_mtok=cache_write_rate * MILLION,
    )
    tokens = TokenCounts(
        input=input_tokens + cache_read_tokens + cache_creation_tokens,
        output=output_tokens,
        cache_read=cache_read_tokens,
        cache_write=cache_creation_tokens,
    )
    return price_tokens(rates, tokens)
