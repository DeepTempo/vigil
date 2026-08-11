"""Rate-table fixtures for the pricing tests (GH #593).

The fixture loads the committed seed SQL rather than a hand-written copy of it.
That is deliberate: a rate mistyped in the seed then shows up as a failing price
assertion here, which is the half of #593's "differently priced in the other
place" criterion that lives on the Python side. The other half is the
cross-language parity fixture both suites read.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
SEED = REPO / "infra/database/init/21_model_rates_seed.sql"
sys.path.insert(0, str(REPO))

# One tuple per INSERT: model_id, provider_type, then the four rates and the source.
_VALUES = re.compile(
    r"VALUES \('([^']+)', '([^']+)', ([\d.]+), ([\d.]+), ([\d.]+), ([\d.]+), '([^']+)'\)"
)


def seed_rows():
    """Every row the committed seed would insert, as ModelRate objects."""
    from core.llm.cost.rates import ModelRate

    rows = []
    for match in _VALUES.finditer(SEED.read_text()):
        model_id, provider, inp, out, read, write, source = match.groups()
        rows.append(
            ModelRate(
                model_id=model_id,
                provider_type=provider,
                input_per_mtok=float(inp),
                output_per_mtok=float(out),
                cache_read_per_mtok=float(read),
                cache_write_per_mtok=float(write),
                pricing_source=source,
            )
        )
    assert rows, f"parsed no rows from {SEED}"
    return rows


@pytest.fixture
def seeded_rates():
    """Load the seed into the frozen table, and forget it again afterwards."""
    from core.llm.cost import rates

    rates.load_rates(seed_rows())
    yield rates
    rates.reset_rates()
