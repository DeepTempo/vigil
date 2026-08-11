# Both languages must price the same call the same. expected_usd is stated in the
# fixture, so neither implementation is the oracle and either drifting fails.

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
FIXTURE = REPO / "tests/fixtures/pricing_parity.json"
sys.path.insert(0, str(REPO))

pytestmark = pytest.mark.unit

CASES = json.loads(FIXTURE.read_text())["cases"]


def ids(cases):
    return [case["name"] for case in cases]


@pytest.mark.parametrize("case", CASES, ids=ids(CASES))
def test_prices_the_shared_case(case, seeded_rates):
    from core.llm.cost.rates import TokenCounts, lookup, price_tokens

    rate = lookup(case["provider_type"], case["model_id"])
    assert rate is not None, f"{case['model_id']} is not priced by the seed"

    tokens = TokenCounts(**case["tokens"])
    assert price_tokens(rate.rates, tokens) == pytest.approx(case["expected_usd"], rel=1e-9)


# Only-uncached cases would pass whatever the formula did with the cached share.
def test_the_fixture_covers_both_cache_directions():
    assert any(case["tokens"]["cache_read"] > 0 for case in CASES)
    assert any(case["tokens"]["cache_write"] > 0 for case in CASES)


# The production entry point, not just the formula: compute_call_cost takes
# Anthropic-native counts, where input excludes both cache shares.
def test_compute_call_cost_agrees_with_the_shared_formula(seeded_rates):
    from core.llm.cost.calls import compute_call_cost

    case = next(c for c in CASES if c["provider_type"] == "anthropic" and c["tokens"]["cache_write"] > 0)
    tokens = case["tokens"]
    native_input = tokens["input"] - tokens["cache_read"] - tokens["cache_write"]

    cost = compute_call_cost(
        case["model_id"],
        case["provider_type"],
        native_input,
        tokens["output"],
        cache_read_tokens=tokens["cache_read"],
        cache_creation_tokens=tokens["cache_write"],
    )
    assert cost == pytest.approx(case["expected_usd"], rel=1e-9)
