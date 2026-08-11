"""The one model rate table, read by both languages (GH #593).

Rates lived in two places — this package's catalog and the agent layer's
configuration — and drifted once, by a factor of three. ``model_rates`` is now
the single source; this module is Python's reader for it.

Read once and frozen. Pricing is on the hot path for every call the gateway
makes, so a per-call query is not an option; a rate change ships as the next
numbered file under ``infra/database/init/`` and is picked up on restart.

Every rate here is USD per **million** tokens, matching the table's column names.
Callers wanting per-token or per-1k divide at their own boundary.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, Iterable, Optional

logger = logging.getLogger(__name__)

MILLION = 1_000_000

# Stands in for a provider whose models cannot be enumerated — self-hosted
# Ollama being the case that exists. Honoured only at pricing_source 'zero', so a
# wildcard can never make a model that should have cost something look free.
WILDCARD = "*"


@dataclass(frozen=True)
class Rates:
    """The four per-million rates the formula needs, without the row's identity.

    Separate from ModelRate so a caller holding rates from somewhere else can
    price with the same arithmetic instead of writing its own.
    """

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
    """What a call consumed, on the one definition both languages use.

    ``input`` is the **total** input, cached share included. That definition is
    the whole point: the two gateway surfaces disagree about it natively —
    OpenAI's ``prompt_tokens`` counts cached tokens, Anthropic's ``input_tokens``
    does not — so each reader normalises to this shape and only one formula
    prices it. Getting that wrong bills the same call two different amounts,
    which is what it did before GH #593.
    """

    input: int
    output: int
    cache_read: int = 0
    cache_write: int = 0


def price_tokens(rates: Rates, tokens: TokenCounts) -> float:
    """USD for one call. The formula, stated once; services/agent/core/budget.ts mirrors it.

    The cached and freshly-written shares are billed at their own rates and
    removed from what is billed at the full input rate. A reader that reports a
    cached share larger than the total clamps to zero rather than crediting.
    """
    fresh = max(0, tokens.input - tokens.cache_read - tokens.cache_write)
    per_million = (
        fresh * rates.input_per_mtok
        + tokens.output * rates.output_per_mtok
        + tokens.cache_read * rates.cache_read_per_mtok
        + tokens.cache_write * rates.cache_write_per_mtok
    )
    return per_million / MILLION


def rate_key(provider_type: str, model_id: str) -> str:
    """The table's ``model_id``: the gateway's own prefixed ``provider/model``.

    Python holds ``provider_type`` and a bare model id separately, so the
    prefixed key is reconstructed here and nowhere else. An id that already
    carries its provider passes through, because the agent layer and Bifrost's
    cost reporting both name models that way.
    """
    prefix = f"{provider_type}/"
    return model_id if model_id.startswith(prefix) else f"{prefix}{model_id}"


def load_rates(rows: Optional[Iterable[ModelRate]] = None) -> Dict[str, ModelRate]:
    """Populate the frozen table, from ``rows`` or from Postgres. Idempotent.

    A database this cannot reach leaves the table empty rather than raising:
    lookups then miss, and the registry falls back to its tier heuristic, which
    is a worse estimate but still an estimate. The agent layer's budget makes the
    opposite choice and refuses, because there a bad number disables a cap.
    """
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
    """Forget the loaded table, so the next lookup reads again."""
    global _TABLE
    _TABLE = None


def lookup(provider_type: str, model_id: str) -> Optional[ModelRate]:
    """The rate for one model, or None when the table does not price it."""
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
