# The projection of a run, written by the agent layer. Phase rows are what the UI
# reads; approval decisions travel back the other way for that layer to journal.

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, Request
from pydantic import BaseModel, Field

from core.agents.internal_auth import authorise
from core.response.checkpoints import raise_for_checkpoint
from core.routing import Auth, RouterMeta

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/internal/runs",
    tags=["internal-runs"],
    auth=Auth.ROUTER_MANAGED,
    reason=(
        "Loopback plus a shared secret: the caller is the agent layer, not a session."
    ),
)
logger = logging.getLogger(__name__)

WAITING = "pending_approval"

# What a run's status becomes when a phase reports one. A step that is waiting is
# the only one that says anything about the run as a whole.
RUN_STATUS = {WAITING: "paused", "running": "running", "completed": "running"}


class PhaseUpdate(BaseModel):
    phase_id: str
    agent: str
    name: str
    order: int
    status: str
    approval_state: Optional[str] = None
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    checkpoint_id: Optional[str] = None
    question: Optional[str] = None


class TerminalUpdate(BaseModel):
    outcome: str
    reason: str = ""
    summary: str = ""


class Decision(BaseModel):
    checkpoint_id: str
    actor: str
    answer: str = Field(..., description="approve or reject")
    text: str = ""
    resolved_at: str


class Decisions(BaseModel):
    decisions: List[Decision] = []


@router.post("/{run_id}/phases", status_code=204)
def record_phase(
    run_id: str,
    update: PhaseUpdate,
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> None:
    from core.workflows.workflow_run_service import get_workflow_run_service

    authorise(request, authorization, "run progress")

    run_service = get_workflow_run_service()
    now = datetime.utcnow()
    run_service.upsert_phase(
        run_id,
        update.phase_id,
        phase_order=update.order,
        agent_id=update.agent,
        status=update.status,
        output=update.output,
        error=update.error,
        # The agent layer says how a gate was answered; a waiting step is the only
        # state this side can name on its own.
        approval_state=update.approval_state
        or ("pending" if update.status == WAITING else None),
        started_at=now if update.status == "running" else None,
        finished_at=now if update.status in ("completed", "failed") else None,
    )
    run_service.set_status(run_id, RUN_STATUS.get(update.status, "running"))

    if update.status == WAITING and update.checkpoint_id:
        _raise_approval(run_id, update)


@router.post("/{run_id}/terminal", status_code=204)
def record_terminal(
    run_id: str,
    update: TerminalUpdate,
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> None:
    from core.workflows.workflow_run_service import get_workflow_run_service

    authorise(request, authorization, "run outcome")

    get_workflow_run_service().finalize_run(
        run_id,
        status="completed" if update.outcome == "completed" else "failed",
        result_summary=update.summary or None,
        error=None if update.outcome == "completed" else update.reason,
    )


# The approvals table is the inbox. An analyst answers there, the agent layer
# reads the answer here, and that layer alone writes it onto the ledger.
@router.get("/{run_id}/decisions", response_model=Decisions)
def list_decisions(
    run_id: str,
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> Decisions:
    from core.response.approval_service import (ActionStatus,
                                                get_approval_service)

    authorise(request, authorization, "run decisions")

    service = get_approval_service()
    decided: List[Decision] = []
    for status, answer in (
        (ActionStatus.APPROVED, "approve"),
        (ActionStatus.REJECTED, "reject"),
    ):
        for action in service.list_actions(status=status, workflow_run_id=run_id):
            checkpoint = (action.parameters or {}).get("checkpoint_id")
            if not checkpoint:
                continue
            decided.append(
                Decision(
                    checkpoint_id=str(checkpoint),
                    actor=action.approved_by or "analyst",
                    answer=answer,
                    text=action.rejection_reason or "",
                    resolved_at=action.approved_at or datetime.utcnow().isoformat(),
                )
            )
    return Decisions(decisions=decided)


# Named by the checkpoint the agent layer raised, so the decision travels back
# addressed to the step that is waiting and to no other.
def _raise_approval(run_id: str, update: PhaseUpdate) -> None:
    raise_for_checkpoint(
        run_id=run_id,
        checkpoint_id=str(update.checkpoint_id),
        title=update.question or f"Approve {update.name}",
        description=update.question or f"Phase {update.order}: {update.name}",
        reason="The playbook marks this phase approval_required",
        parameters={"phase_id": update.phase_id, "agent_id": update.agent},
        phase_id=update.phase_id,
    )
