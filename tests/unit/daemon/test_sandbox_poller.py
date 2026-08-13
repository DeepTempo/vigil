"""SandboxPoller must read and write the column the payload actually lives in.

processor.py stores its enrichment payload nested inside the ai_enrichment
column: ai_enrichment["enrichment"]["sandbox_submissions"]. The poller read a
top-level "enrichment" key, so `pending` was always empty and every run
processed zero findings — silently, because an empty scan looks like success.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from services.daemon.sandbox_poller import SandboxPoller

pytestmark = pytest.mark.unit


def _finding(reports=None):
    """A finding with one pending CAPE submission, shaped as processor writes it."""
    return {
        "finding_id": "f1",
        "case_id": None,
        "ai_enrichment": {
            "ai_triage": {"severity": "high"},
            "enrichment": {
                "sandbox_submissions": {
                    "deadbeef": {"cape": {"task_id": "t1", "status": "pending"}}
                },
                "sandbox_reports": reports or {},
            },
        },
    }


@pytest.fixture
def poller():
    p = SandboxPoller(data_service=MagicMock())
    p._correlation = None
    p._init_services = lambda: None
    p._data_service.update_finding.return_value = True
    return p


async def test_pending_submission_is_found(poller):
    """The regression: this returned checked=0 because the key was wrong."""
    poller._data_service.get_findings.return_value = [_finding()]
    poller._fetch_report = AsyncMock(return_value={"verdict": "malicious"})

    stats = await poller.run_once()

    assert stats["checked"] == 1
    assert stats["completed"] == 1


async def test_report_is_written_back_under_ai_enrichment(poller):
    poller._data_service.get_findings.return_value = [_finding()]
    poller._fetch_report = AsyncMock(return_value={"verdict": "malicious"})

    await poller.run_once()

    _, kwargs = poller._data_service.update_finding.call_args
    assert "enrichment" not in kwargs, "a bare enrichment= kwarg is silently dropped"
    payload = kwargs["ai_enrichment"]
    assert payload["enrichment"]["sandbox_reports"]["deadbeef:cape"]["report"] == {
        "verdict": "malicious"
    }
    assert payload["ai_triage"] == {"severity": "high"}, "must not clobber siblings"


async def test_failed_persist_is_counted(poller):
    poller._data_service.get_findings.return_value = [_finding()]
    poller._fetch_report = AsyncMock(return_value={"verdict": "malicious"})
    poller._data_service.update_finding.return_value = False

    stats = await poller.run_once()

    assert stats["errors"] == 1


async def test_already_reported_submission_is_skipped(poller):
    poller._data_service.get_findings.return_value = [
        _finding(reports={"deadbeef:cape": {"report": {"verdict": "clean"}}})
    ]
    poller._fetch_report = AsyncMock()

    stats = await poller.run_once()

    assert stats["completed"] == 0
    poller._fetch_report.assert_not_awaited()


async def test_finding_without_submissions_is_ignored(poller):
    poller._data_service.get_findings.return_value = [
        {"finding_id": "f2", "ai_enrichment": {"ai_triage": {}}}
    ]

    stats = await poller.run_once()

    assert stats == {"checked": 0, "completed": 0, "expired": 0, "errors": 0}
    poller._data_service.update_finding.assert_not_called()
