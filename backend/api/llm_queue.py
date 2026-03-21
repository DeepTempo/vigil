"""LLM queue management endpoints.

Provides visibility into the ARQ job queues and dead-letter queue (DLQ),
plus a replay endpoint to requeue failed jobs.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class QueueStats(BaseModel):
    queue: str
    pending: int


class DLQEntry(BaseModel):
    ts: str
    job_type: str
    error: str
    messages: List[Dict[str, Any]]


class QueueStatusResponse(BaseModel):
    queues: List[QueueStats]
    dlq_length: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_gateway():
    from services.llm_gateway import get_llm_gateway
    return await get_llm_gateway()


async def _get_redis():
    gw = await _get_gateway()
    return gw._pool


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/llm-queue/status", response_model=QueueStatusResponse)
async def get_queue_status():
    """Return pending job counts for all priority queues and DLQ length."""
    from services.llm_gateway import (
        QUEUE_TRIAGE, QUEUE_INVESTIGATION, QUEUE_CHAT, QUEUE_INSIGHTS, DLQ_KEY
    )
    try:
        redis = await _get_redis()
        queue_names = [QUEUE_TRIAGE, QUEUE_INVESTIGATION, QUEUE_CHAT, QUEUE_INSIGHTS]
        stats = []
        for q in queue_names:
            # ARQ stores pending jobs in a Redis sorted set named <queue>
            count = await redis.zcard(q)
            stats.append(QueueStats(queue=q, pending=count))

        dlq_length = await redis.llen(DLQ_KEY)
        return QueueStatusResponse(queues=stats, dlq_length=dlq_length)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {exc}")


@router.get("/llm-queue/dlq", response_model=List[DLQEntry])
async def list_dlq(limit: int = Query(default=50, le=200)):
    """Return recent dead-letter queue entries (most recent first)."""
    from services.llm_gateway import DLQ_KEY
    try:
        redis = await _get_redis()
        raw_items = await redis.lrange(DLQ_KEY, 0, limit - 1)
        entries = []
        for raw in raw_items:
            try:
                entries.append(DLQEntry(**json.loads(raw)))
            except Exception:
                pass
        return entries
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {exc}")


@router.post("/llm-queue/dlq/replay")
async def replay_dlq(limit: int = Query(default=10, le=100)):
    """Requeue up to *limit* jobs from the DLQ back into the chat queue.

    Jobs are removed from the DLQ upon successful requeue.
    Returns the count of replayed jobs.
    """
    from services.llm_gateway import DLQ_KEY, QUEUE_CHAT
    try:
        redis = await _get_redis()
        gw = await _get_gateway()

        raw_items = await redis.lrange(DLQ_KEY, 0, limit - 1)
        replayed = 0

        for raw in raw_items:
            try:
                entry = json.loads(raw)
                messages = entry.get("messages", [])
                if not messages:
                    continue
                await gw._pool.enqueue_job(
                    "llm_call",
                    messages=messages,
                    model="claude-sonnet-4-6",
                    max_tokens=4096,
                    session_id=None,
                    system_prompt=None,
                    enable_thinking=False,
                    thinking_budget=0,
                    tools=None,
                    temperature=None,
                    job_type="chat",
                    _queue_name=QUEUE_CHAT,
                )
                await redis.lrem(DLQ_KEY, 1, raw)
                replayed += 1
            except Exception as exc:
                logger.warning("Failed to replay DLQ entry: %s", exc)

        return {"replayed": replayed}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Replay failed: {exc}")


@router.delete("/llm-queue/dlq")
async def clear_dlq():
    """Clear all entries from the dead-letter queue."""
    from services.llm_gateway import DLQ_KEY
    try:
        redis = await _get_redis()
        deleted = await redis.llen(DLQ_KEY)
        await redis.delete(DLQ_KEY)
        return {"deleted": deleted}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {exc}")
