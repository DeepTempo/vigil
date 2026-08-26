"""The daemon's synchronous DB calls must not run on the event loop.

The DB layer is synchronous SQLAlchemy (``create_engine`` + ``sessionmaker``
over psycopg2). Any call made from an ``async def`` therefore has to be pushed
through ``asyncio.to_thread`` — awaiting one inline freezes the loop for the
whole round-trip, and ``services/daemon/main.py`` runs eight subsystems on that
single loop, so one blocking write stalls polling, Kafka ingest and the
orchestrator alike.

These tests assert the offload by thread identity rather than by timing, so
they are deterministic: a call that reports the loop's own thread id never
went through a worker thread.
"""

import threading
from unittest.mock import MagicMock, patch

from services.daemon.config import PollingConfig, ProcessingConfig
from services.daemon.poller import DataPoller
from services.daemon.processor import FindingProcessor


class _ThreadRecorder:
    """Stands in for a synchronous DB call and records where it ran."""

    def __init__(self, return_value=True):
        self.thread_id = None
        self.calls = []
        self._return_value = return_value

    def __call__(self, *args, **kwargs):
        self.thread_id = threading.get_ident()
        self.calls.append((args, kwargs))
        return self._return_value


def _assert_offloaded(recorder: _ThreadRecorder, loop_thread: int, name: str):
    assert recorder.thread_id is not None, f"{name} was never called"
    assert recorder.thread_id != loop_thread, (
        f"{name} ran on the event loop thread — it is synchronous SQLAlchemy "
        "and must go through asyncio.to_thread"
    )


async def test_store_finding_offloads_ingest():
    loop_thread = threading.get_ident()
    processor = FindingProcessor(ProcessingConfig())
    recorder = _ThreadRecorder(return_value=True)

    with patch("core.ingestion.ingestion_service.IngestionService") as ingestion_cls:
        ingestion_cls.return_value.ingest_finding = recorder
        stored = await processor._store_finding({"finding_id": "f-1"})

    assert stored is True
    _assert_offloaded(recorder, loop_thread, "ingest_finding")


async def test_update_finding_offloads_the_write():
    loop_thread = threading.get_ident()
    processor = FindingProcessor(ProcessingConfig())
    recorder = _ThreadRecorder()
    processor._data_service = MagicMock()
    processor._data_service.update_finding = recorder

    await processor._update_finding({"finding_id": "f-1", "severity": "high"})

    _assert_offloaded(recorder, loop_thread, "update_finding")
    assert recorder.calls[0][0] == ("f-1",)
    assert recorder.calls[0][1] == {"severity": "high"}


async def test_poller_direct_store_offloads_ingest():
    """The no-queue fallback in _enqueue_finding writes straight to the DB."""
    loop_thread = threading.get_ident()
    poller = DataPoller(PollingConfig())
    poller._output_queue = None  # force the direct-store branch
    poller._data_service = MagicMock()
    recorder = _ThreadRecorder()

    with patch("core.ingestion.ingestion_service.IngestionService") as ingestion_cls:
        ingestion_cls.return_value.ingest_finding = recorder
        await poller._enqueue_finding({"finding_id": "f-1"}, "test-source")

    _assert_offloaded(recorder, loop_thread, "ingest_finding")


async def test_case_review_lookup_offloads_the_query():
    """_maybe_trigger_case_review opens a session to look for an existing
    review, then reads the case. Both are synchronous, and both ran on the
    orchestrator's loop."""
    from services.daemon.config import OrchestratorConfig
    from services.daemon.orchestrator import Orchestrator

    loop_thread = threading.get_ident()
    orchestrator = Orchestrator(OrchestratorConfig())
    recorder = _ThreadRecorder(return_value={"title": "t", "finding_ids": []})
    orchestrator._data_service = MagicMock()
    orchestrator._data_service.get_case = recorder

    with patch("core.storage.connection.get_db_manager") as manager:
        scope = manager.return_value.session_scope.return_value
        scope.__enter__.return_value.query.return_value.filter.return_value.first.return_value = (
            None
        )
        await orchestrator._maybe_trigger_case_review("case-1")

    _assert_offloaded(recorder, loop_thread, "get_case")


async def test_max_concurrent_tasks_is_settings_driven():
    """It gates both the worker-coroutine count and the enrichment LLM cap, so
    it has to be reachable from configuration rather than hard-coded."""
    from core.config import Settings

    assert hasattr(Settings(), "daemon_max_concurrent_tasks")

    config = ProcessingConfig(max_concurrent_tasks=17)
    processor = FindingProcessor(config)
    assert processor._semaphore._value == 17
