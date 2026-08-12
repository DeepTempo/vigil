# Enqueue agent runs onto the queue the TypeScript agent layer consumes. The
# backend enqueues plain JSON and never writes agent_events.

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from bullmq import Queue

from core.config import get_settings

logger = logging.getLogger(__name__)

# No colon: the Node library refuses a queue name containing one, while the
# Python library accepts it and writes the keys anyway. Keys are bull:agent-runs:*.
RUN_QUEUE = "agent-runs"

JOB_SCHEMA_VERSION = 1

DEFAULT_REDIS_URL = "redis://localhost:6379/0"

RUN_KINDS = ("hunt", "investigate", "compose", "chat")


def _redis_url() -> str:
    return get_settings().redis_url or DEFAULT_REDIS_URL


# The reason="start" arm of the RunJob union in the agent layer's job contract.
def build_start_job(
    run_id: str,
    run_kind: str,
    request: Dict[str, Any],
    enqueued_by: str,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "schema_version": JOB_SCHEMA_VERSION,
        "run_id": run_id,
        "run_kind": run_kind,
        "tenant_id": tenant_id,
        "enqueued_at": datetime.now(timezone.utc).isoformat(),
        "enqueued_by": enqueued_by,
        "reason": "start",
        "request": request,
    }


# A resume carries no request: the ledger holds the spec, and what unblocks the
# run is the decision the agent layer reads back, not anything said here.
def build_resume_job(
    run_id: str,
    run_kind: str,
    enqueued_by: str,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "schema_version": JOB_SCHEMA_VERSION,
        "run_id": run_id,
        "run_kind": run_kind,
        "tenant_id": tenant_id,
        "enqueued_at": datetime.now(timezone.utc).isoformat(),
        "enqueued_by": enqueued_by,
        "reason": "resume",
    }


async def enqueue_run(job: Dict[str, Any], job_id: Optional[str] = None) -> str:
    queue = Queue(RUN_QUEUE, {"connection": _redis_url()})
    try:
        # jobId is the run id for a start, so a double POST dedupes inside BullMQ;
        # a resume passes its own, since one run is resumed more than once.
        enqueued = await queue.add("run", job, {"jobId": job_id or job["run_id"]})
        logger.info("enqueued agent run %s (%s)", job["run_id"], job["run_kind"])
        return str(enqueued.id)
    finally:
        await queue.close()


def new_run_id() -> str:
    return str(uuid.uuid4())
