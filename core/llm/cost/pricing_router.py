# What a model costs per token, for the agent layer. The catalog lives here and
# only here -- a second rate table in TypeScript would be one repricing away from
# disagreeing with the dashboard about what a run cost.
#
# Rates rather than a priced call: they are static per model, so the agent asks
# once and multiplies its own token counts. Pricing every call over HTTP would put
# a round trip in the loop's hot path and a failure mode in the one place that must
# never lose a spend event.

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Header, Request

from core.agents.internal_auth import authorise
from core.routing import Auth, RouterMeta

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/internal/pricing",
    tags=["internal-pricing"],
    auth=Auth.ROUTER_MANAGED,
    reason=(
        "Loopback plus a shared secret: the caller is the agent layer, not a session."
    ),
)
logger = logging.getLogger(__name__)


@router.get("/rates")
async def rates(
    model_id: str,
    provider_type: str,
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Per-token USD rates for one model, plus how confidently they resolved."""
    authorise(request, authorization, "pricing lookup")

    from core.llm.providers.registry import get_registry

    registry = get_registry()
    input_per_token, output_per_token = registry.get_cost_rates(model_id, provider_type)
    cache_read, cache_write = registry.get_cache_rates(model_id, provider_type)

    # Carried through rather than resolved away: a $0 call priced from a real
    # catalog entry and a $0 call nobody could price look identical on a ledger,
    # and the fix for each is nothing alike. The agent journals this beside the
    # figure so a run's cost can say how much to trust itself.
    return {
        "input": input_per_token,
        "output": output_per_token,
        "cache_read": cache_read,
        "cache_write": cache_write,
        "source": registry.get_pricing_source(model_id, provider_type),
    }
