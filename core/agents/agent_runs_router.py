# Start an agent run and report its outcome. POST enqueues plain JSON and writes
# nothing; GET makes only the two reads Python is permitted against agent_events.

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text

from core.agents.queue import (
    RUN_KINDS,
    build_start_job,
    enqueue_run,
    new_run_id,
)
from core.routing import Auth, RouterMeta, UnitOfWorkSession

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/agent-runs",
    tags=["agent-runs"],
    auth=Auth.REQUIRED,
)
logger = logging.getLogger(__name__)


class StartRunRequest(BaseModel):
    run_kind: str = Field(default="hunt", description=f"One of {', '.join(RUN_KINDS)}.")
    arch: str = Field(..., description="Path to the arch file: the shape of the run.")
    playbook: str = Field(..., description="Path to the playbook: the scenario as data.")
    config: str = Field(..., description="Path to the deployment config.")
    prompt: str = Field(default="", description="What the run is being asked to do.")
    overrides: Optional[Dict[str, Any]] = None
    tenant_id: Optional[str] = None


class StartRunResponse(BaseModel):
    run_id: str
    job_id: str


class RunStatusResponse(BaseModel):
    run_id: str
    status: str = Field(..., description="running or terminal.")
    events: int = Field(..., description="Events on the ledger, so progress is visible.")
    outcome: Optional[str] = None
    reason: Optional[str] = None


# Mint a run id and enqueue it. The worker opens the ledger, not this call.
@router.post("", response_model=StartRunResponse, status_code=202)
async def start_run(request: StartRunRequest) -> StartRunResponse:
    if request.run_kind not in RUN_KINDS:
        raise HTTPException(status_code=400, detail=f"unknown run_kind: {request.run_kind}")

    run_id = new_run_id()
    payload: Dict[str, Any] = {
        "arch": request.arch,
        "playbook": request.playbook,
        "config": request.config,
        "prompt": request.prompt,
    }
    if request.overrides is not None:
        payload["overrides"] = request.overrides

    job = build_start_job(
        run_id=run_id,
        run_kind=request.run_kind,
        request=payload,
        enqueued_by="api",
        tenant_id=request.tenant_id,
    )
    try:
        job_id = await enqueue_run(job)
    except Exception as exc:  # the queue is the only thing this endpoint can fail on
        logger.error("failed to enqueue agent run %s: %s", run_id, exc)
        raise HTTPException(status_code=503, detail="run queue unavailable") from exc

    return StartRunResponse(run_id=run_id, job_id=job_id)


# Reports from state the worker persisted, using only the two permitted reads.
@router.get("/{run_id}", response_model=RunStatusResponse)
def get_run(run_id: str, session: UnitOfWorkSession) -> RunStatusResponse:
    try:
        uuid.UUID(run_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"no such run: {run_id}") from None

    counted = session.execute(
        text("SELECT count(*) AS events FROM agent_events WHERE run_id = CAST(:run_id AS uuid)"),
        {"run_id": run_id},
    ).one_or_none()
    events = int(counted.events) if counted is not None else 0
    if events == 0:
        raise HTTPException(status_code=404, detail=f"no such run: {run_id}")

    terminal = session.execute(
        text(
            "SELECT payload FROM agent_events "
            "WHERE run_id = CAST(:run_id AS uuid) AND kind = 'terminal' ORDER BY seq LIMIT 1"
        ),
        {"run_id": run_id},
    ).one_or_none()
    if terminal is None:
        return RunStatusResponse(run_id=run_id, status="running", events=events)

    payload = terminal.payload
    return RunStatusResponse(
        run_id=run_id,
        status="terminal",
        events=events,
        outcome=payload.get("outcome"),
        reason=payload.get("reason"),
    )
