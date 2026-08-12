# A checkpoint the agent layer parked on, as an approval a human can answer. The
# answer travels back through /internal/runs/{id}/decisions, which the agent layer
# reads and journals: this side never writes the ledger.

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def pending_for(run_id: str, checkpoint_id: str):
    from core.response.approval_service import (ActionStatus,
                                                get_approval_service)

    service = get_approval_service()
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
) -> bool:
    from core.response.approval_service import ActionType, get_approval_service

    if pending_for(run_id, checkpoint_id) is not None:
        return False

    get_approval_service().create_action(
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
