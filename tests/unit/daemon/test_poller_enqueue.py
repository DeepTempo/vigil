"""The enqueue/dedup contract in DataPoller.

A finding is only ever retried while its dedup key is unmarked. So marking a
finding processed after a failed store drops it permanently — which is what
happened before `_enqueue_finding` reported success. These tests pin that
contract: no acceptance, no mark.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.daemon.config import PollingConfig
from services.daemon.poller import DataPoller

pytestmark = pytest.mark.unit


@pytest.fixture
def poller():
    p = DataPoller(PollingConfig())
    p._federation = MagicMock()
    p._federation.is_active_for.return_value = False
    return p


async def test_queued_finding_is_accepted(poller):
    poller.set_output_queue(asyncio.Queue())
    assert await poller._enqueue_finding({"finding_id": "f1"}, "splunk") is True


async def test_no_queue_and_no_data_service_is_a_drop(poller):
    """Neither sink configured: report the drop rather than returning silently."""
    poller._output_queue = None
    poller._data_service = None
    assert await poller._enqueue_finding({"finding_id": "f1"}, "splunk") is False


async def test_direct_store_success_is_accepted(poller):
    poller._output_queue = None
    poller._data_service = MagicMock()
    with patch(
        "core.ingestion.ingestion_service.IngestionService"
    ) as svc:
        svc.return_value.ingest_finding.return_value = None
        assert await poller._enqueue_finding({"finding_id": "f1"}, "splunk") is True


async def test_direct_store_failure_is_not_accepted(poller):
    poller._output_queue = None
    poller._data_service = MagicMock()
    with patch(
        "core.ingestion.ingestion_service.IngestionService"
    ) as svc:
        svc.return_value.ingest_finding.side_effect = RuntimeError("db down")
        assert await poller._enqueue_finding({"finding_id": "f1"}, "splunk") is False


async def test_failed_store_leaves_the_finding_unmarked(poller):
    """The regression: a dropped finding must stay retryable.

    One bad finding does not abort the batch — the poll returns normally, the
    dedup key simply stays unset so the next tick picks it up again.
    """
    alert = {"id": "a1"}
    poller._elastic_service = MagicMock()
    poller._elastic_service.fetch_alerts = AsyncMock(return_value=[alert])
    poller._elastic_service.transform_alert_to_finding.return_value = {
        "finding_id": "f1"
    }
    poller._elastic_dedup = MagicMock()
    poller._elastic_dedup.is_processed = AsyncMock(return_value=False)
    poller._elastic_dedup.mark_processed = AsyncMock()
    poller._enqueue_finding = AsyncMock(return_value=False)

    await poller._poll_elastic()

    poller._elastic_dedup.mark_processed.assert_not_awaited()
    assert poller.stats["elastic_findings"] == 0


async def test_stored_finding_is_marked(poller):
    alert = {"id": "a1"}
    poller._elastic_service = MagicMock()
    poller._elastic_service.fetch_alerts = AsyncMock(return_value=[alert])
    poller._elastic_service.transform_alert_to_finding.return_value = {
        "finding_id": "f1"
    }
    poller._elastic_dedup = MagicMock()
    poller._elastic_dedup.is_processed = AsyncMock(return_value=False)
    poller._elastic_dedup.mark_processed = AsyncMock()
    poller._enqueue_finding = AsyncMock(return_value=True)

    await poller._poll_elastic()

    poller._elastic_dedup.mark_processed.assert_awaited_once_with("f1")


@pytest.mark.parametrize(
    "source", ["azure_sentinel", "aws_security_hub", "microsoft_defender"]
)
async def test_cloud_pollers_propagate_so_the_loop_counts_the_error(poller, source):
    """Swallowing here let the loop record a successful last_poll_time."""
    service = MagicMock()
    service.ingest_alerts.side_effect = RuntimeError("api down")
    setattr(poller, f"_{source}_service", service)

    with pytest.raises(RuntimeError):
        await getattr(poller, f"_poll_{source}")()
