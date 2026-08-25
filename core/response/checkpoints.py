# A checkpoint the agent layer parked on, as an approval a human can answer. The
# answer goes back via /internal/runs/{id}/decisions; this side never writes the ledger.

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def pending_for(run_id: str, checkpoint_id: str, approvals=None):
    from core.response.approval_service import ActionStatus, ApprovalService

    service = approvals or ApprovalService()
    for action in service.list_actions(
        status=ActionStatus.PENDING, workflow_run_id=run_id
    ):
        if (action.parameters or {}).get("checkpoint_id") == checkpoint_id:
            return action
    return None


# Idempotent by checkpoint, because a supervisor reads the same open checkpoint on
# every tick: raising per read would queue the same question hundreds of times.
def raise_for_checkpoint(
    *,
    run_id: str,
    checkpoint_id: str,
    title: str,
    description: str,
    reason: str,
    parameters: Optional[Dict[str, Any]] = None,
    phase_id: Optional[str] = None,
    approvals=None,
) -> bool:
    from core.response.approval_service import ActionType, ApprovalService

    service = approvals or ApprovalService()
    if pending_for(run_id, checkpoint_id, service) is not None:
        return False

    service.create_action(
        action_type=ActionType.WORKFLOW_PHASE,
        title=title,
        description=description,
        target=run_id,
        confidence=0.0,
        reason=reason,
        evidence=[run_id],
        created_by="agent",
        parameters={"checkpoint_id": checkpoint_id, **(parameters or {})},
        workflow_run_id=run_id,
        workflow_phase_id=phase_id,
    )
    logger.info("raised approval for %s at checkpoint %s", run_id, checkpoint_id)
    return True


# A run that ended is not waiting for anything, and nothing withdrew its question:
# the approvals queue kept filling with questions whose run was over, until a real
# one was buried in them. Rejected rather than deleted, because who asked and why
# it went unanswered is the record.
def withdraw_for_run(run_id: str, reason: str, approvals=None) -> int:
    from core.response.approval_service import ActionStatus, ApprovalService

    service = approvals or ApprovalService()
    open_ones = service.list_actions(
        status=ActionStatus.PENDING, workflow_run_id=run_id
    )
    for action in open_ones:
        service.reject_action(action.action_id, reason, rejected_by="agent")
    if open_ones:
        logger.info("withdrew %d unanswered approvals for %s", len(open_ones), run_id)
    return len(open_ones)
