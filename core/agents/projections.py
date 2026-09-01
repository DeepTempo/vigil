# What a run decided, read from the layer that owns the events. Python is
# permitted two reads against agent_events -- a count and the terminal payload --
# so anything richer is asked for rather than folded here.

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional

from core.config import get_settings
from core.secrets import get_secret

logger = logging.getLogger(__name__)

READ_TIMEOUT_S = 10

# An investigation id is ours and is not a uuid; a run id is. Derived rather than
# stored so the same investigation always addresses the same run.
RUNS = uuid.UUID("6ba7b813-9dad-11d1-80b4-00c04fd430c8")


def run_id_for(investigation_id: str) -> str:
    return str(uuid.uuid5(RUNS, investigation_id))


def agent_route(path: str) -> str:
    return f"{get_settings().agent_url.rstrip('/')}{path}"


def _headers() -> Dict[str, str]:
    token = get_secret("AGENT_INTERNAL_TOKEN") or ""
    if not token:
        raise RuntimeError("AGENT_INTERNAL_TOKEN is not configured")
    return {"Authorization": f"Bearer {token}"}


async def _read_fold(run_id: str, view: str) -> Optional[Dict[str, Any]]:
    import httpx

    url = agent_route(f"/runs/{run_id}/{view}")
    try:
        async with httpx.AsyncClient(timeout=READ_TIMEOUT_S) as client:
            response = await client.get(url, headers=_headers())
    except Exception as exc:  # noqa: BLE001 — unreachable is not terminal
        logger.debug("could not read the %s for %s: %s", view, run_id, exc)
        return None

    if response.status_code == 404:
        return None
    if response.status_code != 200:
        logger.warning("%s for %s answered %s", view, run_id, response.status_code)
        return None
    return response.json()


# None means "nothing to report yet" and is not an error: a run enqueued a moment
# ago has no ledger, and a supervisor must read that as still starting.
async def read_projection(run_id: str) -> Optional[Dict[str, Any]]:
    return await _read_fold(run_id, "projection")


# What episodic memory reads once a run has ended, folded on the side that owns
# the events; see services/agent/workflows/hunt/distil.ts for why it is not the
# projection. None reads as "nothing to distil yet", never as "this run saw
# nothing" — the difference matters, because the second would be a fact.
async def read_distil(run_id: str) -> Optional[Dict[str, Any]]:
    return await _read_fold(run_id, "distil")
