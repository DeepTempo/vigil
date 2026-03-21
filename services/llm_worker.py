"""ARQ worker that processes LLM requests from the queue.

Each priority tier runs as a separate worker process, started via::

    LLM_WORKER_QUEUE=arq:llm:triage       python -m arq services.llm_worker.WorkerSettings
    LLM_WORKER_QUEUE=arq:llm:investigation python -m arq services.llm_worker.WorkerSettings
    LLM_WORKER_QUEUE=arq:llm:chat         python -m arq services.llm_worker.WorkerSettings
    LLM_WORKER_QUEUE=arq:llm:insights     python -m arq services.llm_worker.WorkerSettings

Or use scripts/start_llm_workers.sh to start all four.

Per-queue max concurrency is controlled by LLM_MAX_CONCURRENT_<TYPE>:
  LLM_MAX_CONCURRENT_TRIAGE=3       (default 3)
  LLM_MAX_CONCURRENT_INVESTIGATION=2 (default 2)
  LLM_MAX_CONCURRENT_CHAT=3         (default 3)
  LLM_MAX_CONCURRENT_INSIGHTS=1     (default 1)

On Anthropic 429 errors the worker backs off exponentially (base 2s, max 60s)
before retrying. Permanently failed jobs are written to the dead-letter queue
(Redis key arq:llm:dlq) for later inspection and replay via the API.
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from arq.connections import RedisSettings

sys.path.insert(0, str(Path(__file__).parent.parent))

from services.llm_gateway import (
    QUEUE_TRIAGE,
    QUEUE_INVESTIGATION,
    QUEUE_CHAT,
    QUEUE_INSIGHTS,
    DLQ_KEY,
    RedisSessionStore,
)

logger = logging.getLogger(__name__)

DEFAULT_REDIS_URL = "redis://localhost:6379/0"

# Per-queue concurrency limits
_CONCURRENCY = {
    "triage":        int(os.getenv("LLM_MAX_CONCURRENT_TRIAGE",        "3")),
    "investigation": int(os.getenv("LLM_MAX_CONCURRENT_INVESTIGATION", "2")),
    "chat":          int(os.getenv("LLM_MAX_CONCURRENT_CHAT",          "3")),
    "insights":      int(os.getenv("LLM_MAX_CONCURRENT_INSIGHTS",      "1")),
}

# Backoff settings for Anthropic 429 rate-limit errors
_429_BASE_DELAY = float(os.getenv("LLM_BACKOFF_BASE", "2.0"))   # seconds
_429_MAX_DELAY  = float(os.getenv("LLM_BACKOFF_MAX",  "60.0"))  # seconds
_429_MAX_TRIES  = int(os.getenv("LLM_BACKOFF_MAX_TRIES", "5"))


def _redis_settings() -> RedisSettings:
    url = os.getenv("REDIS_URL", DEFAULT_REDIS_URL)
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return RedisSettings(
        host=parsed.hostname or "localhost",
        port=parsed.port or 6379,
        database=int(parsed.path.lstrip("/") or 0),
        password=parsed.password,
    )


# ---------------------------------------------------------------------------
# 429 backoff helper
# ---------------------------------------------------------------------------

async def _call_with_backoff(fn, *args, **kwargs) -> Any:
    """Run *fn* (sync, called via to_thread) with exponential backoff on 429."""
    delay = _429_BASE_DELAY
    for attempt in range(1, _429_MAX_TRIES + 1):
        try:
            return await asyncio.to_thread(fn, *args, **kwargs)
        except Exception as exc:
            exc_str = str(exc).lower()
            is_429 = (
                "ratelimit" in exc_str
                or "rate_limit" in exc_str
                or "429" in exc_str
                or "overloaded" in exc_str
            )
            if is_429 and attempt < _429_MAX_TRIES:
                logger.warning(
                    "Anthropic rate-limit hit (attempt %d/%d), backing off %.1fs",
                    attempt, _429_MAX_TRIES, delay,
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, _429_MAX_DELAY)
                continue
            raise


# ---------------------------------------------------------------------------
# Worker task functions
# ---------------------------------------------------------------------------

async def llm_call(
    ctx: Dict[str, Any],
    messages: List[Dict],
    model: str,
    max_tokens: int,
    session_id: Optional[str],
    system_prompt: Optional[str],
    enable_thinking: bool,
    thinking_budget: int,
    tools: Optional[List[Dict]],
    temperature: Optional[float],
    job_type: str = "chat",
) -> Any:
    """Execute a single LLM call through the shared ClaudeService.

    1. Acquires the per-type concurrency semaphore
    2. Optionally loads session history from Redis
    3. Calls the Anthropic API (with 429 backoff)
    4. Saves updated session history
    5. Returns the response content; writes to DLQ on permanent failure
    """
    semaphores: Dict[str, asyncio.Semaphore] = ctx["semaphores"]
    claude_service = ctx["claude_service"]
    session_store: RedisSessionStore = ctx["session_store"]

    sem = semaphores.get(job_type) or semaphores["chat"]

    if session_id:
        history = await session_store.load(session_id)
        if history:
            messages = history + messages

    async with sem:
        try:
            response = await _call_with_backoff(
                _sync_claude_call,
                claude_service,
                messages=messages,
                model=model,
                max_tokens=max_tokens,
                system_prompt=system_prompt,
                enable_thinking=enable_thinking,
                thinking_budget=thinking_budget,
                tools=tools,
                temperature=temperature,
            )
        except Exception as exc:
            await _write_dlq(ctx, job_type=job_type, messages=messages, error=str(exc))
            raise

    result = _extract_result(response)

    if session_id:
        updated = messages + [{"role": "assistant", "content": result.get("content", "")}]
        await session_store.save(session_id, updated)

    return result


async def llm_call_raw(
    ctx: Dict[str, Any],
    messages: List[Dict],
    model: str,
    max_tokens: int,
    enable_thinking: bool,
    thinking_budget: int,
    tools: Optional[List[Dict]],
    temperature: Optional[float],
    job_type: str = "investigation",
) -> Dict[str, Any]:
    """Execute a raw multi-turn LLM call (used by AgentRunner tool loop).

    Unlike ``llm_call``, this does NOT manage sessions — the caller
    provides the full message list including assistant/tool_result turns.
    Returns the raw Anthropic response as a serialisable dict.
    """
    semaphores: Dict[str, asyncio.Semaphore] = ctx["semaphores"]
    claude_service = ctx["claude_service"]

    sem = semaphores.get(job_type) or semaphores["investigation"]

    async with sem:
        try:
            response = await _call_with_backoff(
                _sync_claude_raw,
                claude_service,
                messages=messages,
                model=model,
                max_tokens=max_tokens,
                enable_thinking=enable_thinking,
                thinking_budget=thinking_budget,
                tools=tools,
                temperature=temperature,
            )
        except Exception as exc:
            await _write_dlq(ctx, job_type=job_type, messages=messages, error=str(exc))
            raise

    return _serialize_raw_response(response)


# ---------------------------------------------------------------------------
# Dead-letter queue helper
# ---------------------------------------------------------------------------

async def _write_dlq(
    ctx: Dict[str, Any],
    *,
    job_type: str,
    messages: List[Dict],
    error: str,
):
    try:
        redis = ctx["redis"]
        entry = json.dumps(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "job_type": job_type,
                "error": error,
                "messages": messages,
            },
            default=str,
        )
        await redis.lpush(DLQ_KEY, entry)
        await redis.ltrim(DLQ_KEY, 0, 999)
        logger.error("Job written to DLQ (type=%s): %s", job_type, error)
    except Exception as dlq_exc:
        logger.error("Failed to write to DLQ: %s", dlq_exc)


# ---------------------------------------------------------------------------
# Sync helpers (run inside asyncio.to_thread)
# ---------------------------------------------------------------------------

def _sync_claude_call(
    claude_service,
    *,
    messages: List[Dict],
    model: str,
    max_tokens: int,
    system_prompt: Optional[str],
    enable_thinking: bool,
    thinking_budget: int,
    tools: Optional[List[Dict]],
    temperature: Optional[float],
) -> Any:
    current_message = messages[-1]["content"] if messages else ""
    context = messages[:-1] if len(messages) > 1 else None

    return claude_service.chat(
        message=current_message,
        context=context,
        system_prompt=system_prompt,
        model=model,
        max_tokens=max_tokens,
        enable_thinking=enable_thinking,
        thinking_budget=thinking_budget if enable_thinking else None,
    )


def _sync_claude_raw(
    claude_service,
    *,
    messages: List[Dict],
    model: str,
    max_tokens: int,
    enable_thinking: bool,
    thinking_budget: int,
    tools: Optional[List[Dict]],
    temperature: Optional[float],
) -> Any:
    kwargs: Dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": messages,
    }
    if tools:
        kwargs["tools"] = tools
    if temperature is not None:
        kwargs["temperature"] = temperature
    if enable_thinking and thinking_budget:
        kwargs["thinking"] = {
            "type": "enabled",
            "budget_tokens": thinking_budget,
        }

    return claude_service.client.messages.create(**kwargs)


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _extract_result(response: Any) -> Dict[str, Any]:
    if response is None:
        return {"content": "", "type": "error", "error": "Empty response"}
    if isinstance(response, str):
        return {"content": response, "type": "text"}
    if isinstance(response, list):
        return {"content": response, "type": "blocks"}
    if isinstance(response, dict):
        return response
    return {"content": str(response), "type": "text"}


def _serialize_raw_response(response: Any) -> Dict[str, Any]:
    try:
        content_blocks = []
        for block in response.content:
            if block.type == "text":
                content_blocks.append({"type": "text", "text": block.text})
            elif block.type == "tool_use":
                content_blocks.append({
                    "type": "tool_use",
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })
            elif block.type == "thinking":
                thinking_block = {"type": "thinking", "thinking": block.thinking}
                if hasattr(block, "signature") and block.signature:
                    thinking_block["signature"] = block.signature
                content_blocks.append(thinking_block)

        return {
            "content": content_blocks,
            "stop_reason": response.stop_reason,
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
        }
    except Exception as e:
        logger.error("Failed to serialise raw response: %s", e)
        return {
            "content": [],
            "stop_reason": "error",
            "input_tokens": 0,
            "output_tokens": 0,
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# Worker startup / shutdown
# ---------------------------------------------------------------------------

async def on_startup(ctx: Dict[str, Any]):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    queue = os.getenv("LLM_WORKER_QUEUE", QUEUE_CHAT)
    # Determine job_type from queue name (arq:llm:<type>)
    job_type = queue.rsplit(":", 1)[-1] if ":" in queue else "chat"
    concurrency = _CONCURRENCY.get(job_type, _CONCURRENCY["chat"])

    from services.claude_service import ClaudeService

    claude_service = ClaudeService(
        use_backend_tools=True,
        use_mcp_tools=True,
        use_agent_sdk=False,
        enable_thinking=True,
        thinking_budget=8000,
    )
    ctx["claude_service"] = claude_service
    # One semaphore per type, shared across all jobs processed by this worker
    ctx["semaphores"] = {t: asyncio.Semaphore(c) for t, c in _CONCURRENCY.items()}
    ctx["session_store"] = RedisSessionStore(ctx["redis"])
    ctx["job_type"] = job_type

    logger.info(
        "LLM worker started (queue=%s, job_type=%s, concurrency=%d)",
        queue, job_type, concurrency,
    )


async def on_shutdown(ctx: Dict[str, Any]):
    logger.info("LLM worker shutting down (queue=%s)", ctx.get("job_type", "?"))


# ---------------------------------------------------------------------------
# ARQ WorkerSettings
#
# The active queue is selected at startup via LLM_WORKER_QUEUE env var.
# Run one process per queue for true priority isolation.
# ---------------------------------------------------------------------------

def _active_queue() -> str:
    return os.getenv("LLM_WORKER_QUEUE", QUEUE_CHAT)


def _active_max_jobs() -> int:
    queue = _active_queue()
    job_type = queue.rsplit(":", 1)[-1] if ":" in queue else "chat"
    return _CONCURRENCY.get(job_type, _CONCURRENCY["chat"])


class WorkerSettings:
    """ARQ worker configuration.

    Start one process per priority tier::

        LLM_WORKER_QUEUE=arq:llm:triage       python -m arq services.llm_worker.WorkerSettings
        LLM_WORKER_QUEUE=arq:llm:investigation python -m arq services.llm_worker.WorkerSettings
        LLM_WORKER_QUEUE=arq:llm:chat         python -m arq services.llm_worker.WorkerSettings
        LLM_WORKER_QUEUE=arq:llm:insights     python -m arq services.llm_worker.WorkerSettings

    Or use scripts/start_llm_workers.sh.
    """
    functions = [llm_call, llm_call_raw]
    redis_settings = _redis_settings()
    queue_name = _active_queue()
    max_jobs = _active_max_jobs()
    job_timeout = 180
    retry_jobs = True
    max_tries = 3
    on_startup = on_startup
    on_shutdown = on_shutdown
