# Python's reader for model_rates, the one rate table both languages read.
# Read once and frozen; every rate is USD per MILLION tokens.

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, Iterable, Optional

logger = logging.getLogger(__name__)

MILLION = 1_000_000

# Stands in for a provider whose models cannot be enumerated. Honoured only at
# pricing_source 'zero', so it can never make a model that should cost look free.
WILDCARD = "*"


@dataclass(frozen=True)
class Rates:
    # Separate from ModelRate so a caller holding rates from elsewhere prices
    # with the same arithmetic instead of writing its own.
    input_per_mtok: float
    output_per_mtok: float
    cache_read_per_mtok: float
    cache_write_per_mtok: float


@dataclass(frozen=True)
class ModelRate:
    model_id: str
    provider_type: str
    input_per_mtok: float
    output_per_mtok: float
    cache_read_per_mtok: float
    cache_write_per_mtok: float
    pricing_source: str

    @property
    def rates(self) -> Rates:
        return Rates(
            input_per_mtok=self.input_per_mtok,
            output_per_mtok=self.output_per_mtok,
            cache_read_per_mtok=self.cache_read_per_mtok,
            cache_write_per_mtok=self.cache_write_per_mtok,
        )


_TABLE: Optional[Dict[str, ModelRate]] = None

_SELECT = (
    "SELECT model_id, provider_type, input_per_mtok, output_per_mtok, "
    "cache_read_per_mtok, cache_write_per_mtok, pricing_source FROM model_rates"
)


@dataclass(frozen=True)
class TokenCounts:
    # input is the TOTAL input, cached share included. The two gateway surfaces
    # disagree natively, so each reader normalises here and one formula prices it.
    input: int
    output: int
    cache_read: int = 0
    cache_write: int = 0


# USD for one call, the formula stated once; services/agent/core/budget.ts mirrors it.
# Cached and written shares bill at their own rates, removed from the full input rate.
def price_tokens(rates: Rates, tokens: TokenCounts) -> float:
    fresh = max(0, tokens.input - tokens.cache_read - tokens.cache_write)
    per_million = (
        fresh * rates.input_per_mtok
        + tokens.output * rates.output_per_mtok
        + tokens.cache_read * rates.cache_read_per_mtok
        + tokens.cache_write * rates.cache_write_per_mtok
    )
    return per_million / MILLION


# The table's model_id: the gateway's prefixed provider/model. Python holds the two
# separately, so the key is reconstructed here and nowhere else.
def rate_key(provider_type: str, model_id: str) -> str:
    prefix = f"{provider_type}/"
    return model_id if model_id.startswith(prefix) else f"{prefix}{model_id}"


# Idempotent. An unreachable database leaves the table empty rather than raising, so
# lookups miss and the registry falls back to its tier heuristic.
def load_rates(rows: Optional[Iterable[ModelRate]] = None) -> Dict[str, ModelRate]:
    global _TABLE
    if rows is not None:
        _TABLE = {rate_key(rate.provider_type, rate.model_id): rate for rate in rows}
        return _TABLE
    if _TABLE is not None:
        return _TABLE
    _TABLE = _read()
    logger.info("model_rates loaded: %d rows", len(_TABLE))
    return _TABLE


def reset_rates() -> None:
    global _TABLE
    _TABLE = None


# The rate for one model, or None when the table does not price it.
def lookup(provider_type: str, model_id: str) -> Optional[ModelRate]:
    table = load_rates()
    exact = table.get(rate_key(provider_type, model_id))
    if exact is not None:
        return exact
    wildcard = table.get(rate_key(provider_type, WILDCARD))
    return wildcard if wildcard is not None and wildcard.pricing_source == "zero" else None


def _read() -> Dict[str, ModelRate]:
    try:
        from sqlalchemy import text

        from core.storage.connection import get_db_session

        session = get_db_session()
        try:
            rows = session.execute(text(_SELECT)).all()
        finally:
            session.close()
    except Exception as exc:  # noqa: BLE001 — an unreachable table is not fatal here
        logger.warning("model_rates unavailable (%s); falling back to tier estimates", exc)
        return {}
    return {rate_key(row.provider_type, row.model_id): _rate(row) for row in rows}


def _rate(row: object) -> ModelRate:
    return ModelRate(
        model_id=str(getattr(row, "model_id")),
        provider_type=str(getattr(row, "provider_type")),
        input_per_mtok=float(getattr(row, "input_per_mtok")),
        output_per_mtok=float(getattr(row, "output_per_mtok")),
        cache_read_per_mtok=float(getattr(row, "cache_read_per_mtok")),
        cache_write_per_mtok=float(getattr(row, "cache_write_per_mtok")),
        pricing_source=str(getattr(row, "pricing_source")),
    )
