# What a decision does to a paused run. The answer is already recorded on the
# approval action; this only tells the agent layer there is one to read.

from __future__ import annotations

import logging
from typing import Any, Dict

from core.agents.queue import build_resume_job, enqueue_run
from core.workflows.workflows_service import COMPOSE_RUN_KIND

logger = logging.getLogger(__name__)


async def resume_run(run_id: str, action_id: str, decided_by: str) -> Dict[str, Any]:
    """Ask the agent layer to pick ``run_id`` back up after a decision."""
    job = build_resume_job(
        run_id=run_id, run_kind=COMPOSE_RUN_KIND, enqueued_by=decided_by
    )
    try:
        # One decision, one resume: the action id is what makes a double click on
        # approve the same job rather than two runs of the same step.
        job_id = await enqueue_run(job, job_id=f"{run_id}:{action_id}")
    except Exception as exc:  # noqa: BLE001
        logger.error("could not resume run %s: %s", run_id, exc)
        return {"success": False, "run_id": run_id, "error": "run queue unavailable"}

    return {"success": True, "status": "resuming", "run_id": run_id, "job_id": job_id}
