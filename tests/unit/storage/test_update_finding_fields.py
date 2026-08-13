"""update_finding must say when it ignores a field.

Unknown keys are skipped rather than rejected — the S3 sync path passes whole
external finding dicts — but a silent skip is how a typo'd column name became a
no-op that still returned True (see the sandbox poller fix).
"""

from unittest.mock import MagicMock, patch

import pytest

from core.storage.service import DatabaseService

pytestmark = pytest.mark.unit


@pytest.fixture
def service():
    with patch("core.storage.service.get_db_manager"):
        return DatabaseService()


def _session_with(finding, service):
    session = MagicMock()
    session.get.return_value = finding
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=session)
    ctx.__exit__ = MagicMock(return_value=False)
    service.db_manager.session_scope.return_value = ctx
    return session


def test_known_field_is_applied(service):
    finding = MagicMock(spec=["severity", "updated_at"])
    _session_with(finding, service)

    assert service.update_finding("f1", severity="high") is True
    assert finding.severity == "high"


def test_unknown_field_is_reported(service, caplog):
    finding = MagicMock(spec=["severity", "updated_at"])
    _session_with(finding, service)

    with caplog.at_level("WARNING"):
        assert service.update_finding("f1", enrichment={"a": 1}) is True

    assert "unknown field" in caplog.text
    assert "enrichment" in caplog.text


def test_known_fields_still_applied_alongside_an_unknown_one(service):
    finding = MagicMock(spec=["severity", "updated_at"])
    _session_with(finding, service)

    service.update_finding("f1", severity="low", nonsense=1)

    assert finding.severity == "low"


def test_all_known_fields_log_nothing(service, caplog):
    finding = MagicMock(spec=["severity", "updated_at"])
    _session_with(finding, service)

    with caplog.at_level("WARNING"):
        service.update_finding("f1", severity="high")

    assert "unknown field" not in caplog.text
