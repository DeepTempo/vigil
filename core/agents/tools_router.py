# The one way the TypeScript agent layer reaches a Python tool. Bounds are applied
# here rather than after serialisation, which would malform the result.

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Header
from pydantic import BaseModel, Field

from core.agents.internal_auth import authorise
from core.agents.tool_registry import execute_backend_tool
from core.routing import Auth, RouterMeta

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/internal/tools",
    tags=["internal-tools"],
    auth=Auth.ROUTER_MANAGED,
    reason=(
        "A shared secret: the caller is the agent layer, not a session. Reachability\n"
        "is the NetworkPolicy's job since ADR 0014, not a loopback check."
    ),
)
logger = logging.getLogger(__name__)

SOURCE_SYSTEM = "vigil"


class Bounds(BaseModel):
    max_rows: int = Field(..., gt=0)
    timeout_ms: int = Field(..., gt=0)


class InvokeRequest(BaseModel):
    tool: str
    args: Dict[str, Any] = Field(default_factory=dict)
    bounds: Bounds


def _failure(kind: str, **detail: Any) -> Dict[str, Any]:
    return {"ok": False, "failure": {"kind": kind, **detail}}


# Whatever the ladder returned, as rows. A bare mapping is one row rather than no
# rows, so a tool answering with a single object is not read as an empty result.
def _rows(result: Any) -> List[Any]:
    if result is None:
        return []
    if isinstance(result, list):
        return result
    return [result]


# The ladder reports an unknown name in-band rather than raising, so that shape has
# to be read back out as the defect it is.
def _errored(result: Any) -> Optional[str]:
    if isinstance(result, dict) and isinstance(result.get("error"), str):
        return result["error"]
    return None


async def _run(body: InvokeRequest) -> Tuple[Any, bool]:
    return await asyncio.wait_for(
        execute_backend_tool(body.tool, body.args),
        timeout=body.bounds.timeout_ms / 1000,
    )


@router.post("/invoke")
async def invoke(
    body: InvokeRequest,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    authorise(authorization, "tool invocation")

    try:
        result, handled = await _run(body)
    except asyncio.TimeoutError:
        return _failure("timeout", timeoutMs=body.bounds.timeout_ms)
    except TypeError as exc:
        return _failure("invalid_args", detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.exception("tool %s failed", body.tool)
        return _failure("backend_error", detail=str(exc))

    if not handled:
        return _failure("refused", detail=f"no such tool: {body.tool}")
    errored = _errored(result)
    if errored is not None:
        return _failure("refused", detail=errored)

    rows = _rows(result)
    capped = len(rows) > body.bounds.max_rows
    return {
        "ok": True,
        "rows": rows[: body.bounds.max_rows],
        "rowCount": min(len(rows), body.bounds.max_rows),
        "capped": capped,
        "sourceSystem": SOURCE_SYSTEM,
    }
