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
        # No job id of our own. It used to be f"{run_id}:{action_id}", so that a
        # double click on approve was one job -- but a resume that *fails* keeps
        # that id in the queue, and every later attempt at the same decision is
        # then dropped as a duplicate, wedging the run on the one approval it was
        # waiting for. Run-level exclusion belongs to agent_run_leases, which
        # refuses the second worker whatever the queue let through: a double click
        # now costs one job that claims and one that returns having found the run
        # already being driven.
        job_id = await enqueue_run(job)
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "could not resume run %s after decision %s: %s", run_id, action_id, exc
        )
        return {"success": False, "run_id": run_id, "error": "run queue unavailable"}

    return {"success": True, "status": "resuming", "run_id": run_id, "job_id": job_id}
