"""Both languages must price the same call the same (GH #593).

The rates were the visible drift — a config shipped one three times too high —
but the formula was drifting too, and a rate-parity check would not have caught
it: Python billed input excluding the cached share while the agent layer billed
it including. Same tokens, same rates, two different dollar figures.

So the fixture states expected_usd itself, hand-computed from the committed seed,
and both suites reproduce it. Neither implementation is the oracle, and a formula
changed in one language and not the other fails here or in
``services/agent/tests/pricing-parity.test.ts``.
"""

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


def test_the_fixture_covers_both_cache_directions():
    """A fixture of only uncached calls would pass whatever the formula did with
    the cached share, which is the exact thing being pinned."""
    assert any(case["tokens"]["cache_read"] > 0 for case in CASES)
    assert any(case["tokens"]["cache_write"] > 0 for case in CASES)


def test_compute_call_cost_agrees_with_the_shared_formula(seeded_rates):
    """The production entry point, not just the formula underneath it.

    compute_call_cost takes Anthropic-native counts, where input excludes both
    cache shares, so it must reach the same dollars as the fixture case that
    states the total.
    """
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
