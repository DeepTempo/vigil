# The projection of a run, written by the agent layer. Phase rows are what the UI
# reads; approval decisions travel back the other way for that layer to journal.

from __future__ import annotations

import logging
from core.time import utcnow
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header
from pydantic import BaseModel, Field

from core.agents.internal_auth import authorise
from core.deps import provide_approvals, provide_workflow_runs
from core.response.approval_service import ApprovalService
from core.response.checkpoints import raise_for_checkpoint, withdraw_for_run
from core.routing import Auth, RouterMeta
from core.workflows.workflow_run_service import WorkflowRunService

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/internal/runs",
    tags=["internal-runs"],
    auth=Auth.ROUTER_MANAGED,
    reason=(
        "A shared secret: the caller is the agent layer, not a session. Reachability\n"
        "is the NetworkPolicy's job since ADR 0014, not a loopback check."
    ),
)
logger = logging.getLogger(__name__)

WAITING = "pending_approval"

# What a run's status becomes when a phase reports one. A step that is waiting is
# the only one that says anything about the run as a whole.
RUN_STATUS = {WAITING: "paused", "running": "running", "completed": "running"}

# A run nobody stopped and nothing broke. Aborted and abandoned both read as
# crashes under "failed", and only one of the three is worth paging over.
TERMINAL_STATUS = {
    "completed": "completed",
    "aborted": "cancelled",
    "abandoned": "cancelled",
}


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


class TerminalHandoff(BaseModel):
    case_id: str
    title: str
    markdown: str = ""


class TerminalUpdate(BaseModel):
    outcome: str
    reason: str = ""
    summary: str = ""
    cost_usd: Optional[float] = None
    handoffs: List[TerminalHandoff] = Field(default_factory=list)


class CheckpointRaised(BaseModel):
    checkpoint_id: str
    checkpoint_class: str
    question: str
    raised_at: str = ""
    run_kind: str = ""
    context: Optional[Dict[str, Any]] = None


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
    authorization: Optional[str] = Header(default=None),
    run_service: WorkflowRunService = Depends(provide_workflow_runs),
    approvals: ApprovalService = Depends(provide_approvals),
) -> None:
    authorise(authorization, "run progress")

    now = utcnow()
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
        _raise_approval(run_id, update, approvals)


@router.post("/{run_id}/terminal", status_code=204)
def record_terminal(
    run_id: str,
    update: TerminalUpdate,
    authorization: Optional[str] = Header(default=None),
    run_service: WorkflowRunService = Depends(provide_workflow_runs),
    approvals: ApprovalService = Depends(provide_approvals),
) -> None:
    authorise(authorization, "run outcome")

    withdraw_for_run(
        run_id,
        f"the run ended before this was answered: {update.reason or update.outcome}",
        approvals,
    )

    run_service.finalize_run(
        run_id,
        status=TERMINAL_STATUS.get(update.outcome, "failed"),
        result_summary=update.summary or None,
        error=None if update.outcome == "completed" else update.reason,
        cost_usd=update.cost_usd,
    )

    for handoff in update.handoffs:
        _open_case(run_id, handoff)


# A run that ended by handing work over opens the case that receives it. The agent
# layer holds no case table, so the document travels and this side files it.
def _open_case(run_id: str, handoff: TerminalHandoff) -> None:
    from core.storage.database_data_service import DatabaseDataService

    try:
        DatabaseDataService().create_case(
            title=handoff.title[:200],
            finding_ids=[],
            priority="high",
            description=handoff.markdown,
        )
    except Exception:  # noqa: BLE001 — the run ended either way
        logger.exception("could not open %s handed off by %s", handoff.case_id, run_id)


# A run parked on a checkpoint, as a question in the approvals inbox. Only the
# compose path raised these before, so a hunt parked where nobody could see it.
@router.post("/{run_id}/checkpoints", status_code=204)
def record_checkpoint(
    run_id: str,
    raised: CheckpointRaised,
    authorization: Optional[str] = Header(default=None),
    approvals: ApprovalService = Depends(provide_approvals),
) -> None:
    authorise(authorization, "run checkpoint")

    # Idempotent per checkpoint inside raise_for_checkpoint, because a parked run
    # is announced on every sweep and would otherwise queue the question each time.
    raise_for_checkpoint(
        run_id=run_id,
        checkpoint_id=raised.checkpoint_id,
        title=raised.question[:120] or raised.checkpoint_class,
        description=raised.question,
        reason=f"The run parked on a {raised.checkpoint_class} checkpoint",
        parameters={
            "checkpoint_class": raised.checkpoint_class,
            "run_kind": raised.run_kind,
            **(raised.context or {}),
        },
        approvals=approvals,
    )


# The approvals table is the inbox. An analyst answers there, the agent layer
# reads the answer here, and that layer alone writes it onto the ledger.
@router.get("/{run_id}/decisions", response_model=Decisions)
def list_decisions(
    run_id: str,
    authorization: Optional[str] = Header(default=None),
    approvals: ApprovalService = Depends(provide_approvals),
) -> Decisions:
    from core.response.approval_service import ActionStatus

    authorise(authorization, "run decisions")

    decided: List[Decision] = []
    for status, answer in (
        (ActionStatus.APPROVED, "approve"),
        (ActionStatus.REJECTED, "reject"),
    ):
        for action in approvals.list_actions(status=status, workflow_run_id=run_id):
            checkpoint = (action.parameters or {}).get("checkpoint_id")
            if not checkpoint:
                continue
            decided.append(
                Decision(
                    checkpoint_id=str(checkpoint),
                    actor=action.approved_by or "analyst",
                    answer=answer,
                    text=action.rejection_reason or "",
                    resolved_at=action.approved_at or utcnow().isoformat(),
                )
            )
    return Decisions(decisions=decided)


# Named by the checkpoint the agent layer raised, so the decision travels back
# addressed to the step that is waiting and to no other.
def _raise_approval(
    run_id: str, update: PhaseUpdate, approvals: ApprovalService
) -> None:
    raise_for_checkpoint(
        run_id=run_id,
        checkpoint_id=str(update.checkpoint_id),
        title=update.question or f"Approve {update.name}",
        description=update.question or f"Phase {update.order}: {update.name}",
        reason="The playbook marks this phase approval_required",
        parameters={"phase_id": update.phase_id, "agent_id": update.agent},
        phase_id=update.phase_id,
        approvals=approvals,
    )
