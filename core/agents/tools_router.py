# The one way the TypeScript agent layer reaches a Python tool. Bounds are applied
# here rather than after serialisation, which would malform the result.

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Header
from pydantic import BaseModel, Field

from core.agents.internal_auth import authorise
from core.agents.mcp_tools import MCPFailure, execute_mcp_tool
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


# The ladder reports a failure in-band rather than raising, so that shape is read
# back out here.
def _errored(result: Any) -> Optional[str]:
    if isinstance(result, dict) and isinstance(result.get("error"), str):
        return result["error"]
    return None


# Python's wording for a call that did not fit its signature. A TypeError from
# inside a tool is not one, and invalid_args tells the model to retry until the cap.
_SIGNATURE_MISMATCH = (
    "unexpected keyword argument",
    "required positional argument",
    "required keyword-only argument",
    "positional argument",
)


def _is_bad_arguments(exc: TypeError) -> bool:
    return any(phrase in str(exc) for phrase in _SIGNATURE_MISMATCH)


# The cap reaches the tool rather than only its answer, for anything paging on limit.
# What ignores it is still truncated below: a bound an adapter drops is not a bound.
def _bounded(args: Dict[str, Any], max_rows: int) -> Dict[str, Any]:
    requested = args.get("limit")
    if isinstance(requested, int) and requested <= max_rows:
        return args
    return {**args, "limit": max_rows}


# Backend tools first, then the MCP servers. One ceiling governs both, so a tool
# does not get a second timeout by virtue of living on the other side.
async def _run(body: InvokeRequest) -> Tuple[Any, bool]:
    seconds = body.bounds.timeout_ms / 1000
    args = _bounded(body.args, body.bounds.max_rows)

    result, handled = await asyncio.wait_for(
        execute_backend_tool(body.tool, args), timeout=seconds
    )
    if handled:
        return result, True
    return await asyncio.wait_for(
        execute_mcp_tool(body.tool, args, seconds), timeout=seconds
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
    # An MCP server that could not be reached is a gap in visibility, not a defect
    # in the call, and the hunt records the two differently.
    except MCPFailure as exc:
        if exc.kind == "timeout":
            return _failure("timeout", timeoutMs=body.bounds.timeout_ms)
        return _failure(exc.kind, detail=exc.detail)
    except TypeError as exc:
        if _is_bad_arguments(exc):
            return _failure("invalid_args", detail=str(exc))
        logger.exception("tool %s failed", body.tool)
        return _failure("backend_error", detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.exception("tool %s failed", body.tool)
        return _failure("backend_error", detail=str(exc))

    # refused is for a name nothing implements. A tool that ran and could not
    # answer is a backend_error: the contract keeps the two apart deliberately.
    if not handled:
        return _failure("refused", detail=f"no such tool: {body.tool}")
    errored = _errored(result)
    if errored is not None:
        return _failure("backend_error", detail=errored)

    rows = _rows(result)
    capped = len(rows) > body.bounds.max_rows
    return {
        "ok": True,
        "rows": rows[: body.bounds.max_rows],
        "rowCount": min(len(rows), body.bounds.max_rows),
        "capped": capped,
        "sourceSystem": SOURCE_SYSTEM,
    }
