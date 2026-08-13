"""The daemon health check must notice a dead database.

It used to infer health from `get_findings()`, which returns [] on failure —
so an unreachable database reported healthy with a findings_count of 0.
"""

from unittest.mock import MagicMock, patch

import pytest

from services.daemon.config import SchedulerConfig
from services.daemon.scheduler import TaskScheduler

pytestmark = pytest.mark.unit


@pytest.fixture
def scheduler():
    s = TaskScheduler(SchedulerConfig())
    s._data_service = MagicMock()
    s._claude_service = MagicMock()
    return s


async def test_healthy_when_database_responds(scheduler):
    scheduler._data_service.get_findings.return_value = [object(), object()]
    with patch("services.daemon.scheduler.get_db_manager") as m:
        m.return_value.health_check.return_value = True
        health = await scheduler._run_health_check()

    assert health["status"] == "healthy"
    assert health["components"]["database"]["findings_count"] == 2


async def test_degraded_when_database_is_unreachable(scheduler):
    """The regression: get_findings() returning [] must not read as healthy."""
    scheduler._data_service.get_findings.return_value = []
    with patch("services.daemon.scheduler.get_db_manager") as m:
        m.return_value.health_check.return_value = False
        health = await scheduler._run_health_check()

    assert health["status"] == "degraded"
    assert health["components"]["database"]["status"] == "error"


async def test_no_data_service_is_unavailable_not_error(scheduler):
    scheduler._data_service = None
    health = await scheduler._run_health_check()

    assert health["components"]["database"]["status"] == "unavailable"


async def test_missing_claude_service_is_reported(scheduler):
    scheduler._claude_service = None
    with patch("services.daemon.scheduler.get_db_manager") as m:
        m.return_value.health_check.return_value = True
        health = await scheduler._run_health_check()

    assert health["components"]["claude"]["status"] == "unavailable"
