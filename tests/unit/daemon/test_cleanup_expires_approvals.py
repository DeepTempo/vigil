"""The scheduled cleanup actually expires stale approvals, at the configured window.

The wiring is the risk here, not the sweep. `_run_cleanup` shipped as a stub that
computed a cutoff and only logged it, so "cleanup runs" was true while nothing was
cleaned. A sweep that is registered but never reached, or reached with the wrong
window, fails exactly the same silent way (#675).
"""

from unittest.mock import patch

import pytest

from services.daemon.config import SchedulerConfig
from services.daemon.scheduler import TaskScheduler

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_cleanup_expires_approvals_using_the_configured_window():
    config = SchedulerConfig()
    config.approval_expiry_days = 3
    scheduler = TaskScheduler(config)

    with patch("core.response.checkpoints.expire_stale", return_value=2) as sweep:
        result = await scheduler._run_cleanup()

    sweep.assert_called_once_with(3)
    assert result["approvals_expired"] == 2


@pytest.mark.asyncio
async def test_cleanup_reports_zero_when_nothing_is_stale():
    scheduler = TaskScheduler(SchedulerConfig())

    with patch("core.response.checkpoints.expire_stale", return_value=0):
        result = await scheduler._run_cleanup()

    assert result["approvals_expired"] == 0
    # The data-retention half is still only logged; the cutoff it reports must
    # not quietly disappear when the approval sweep is added alongside it.
    assert "cutoff_date" in result


def test_the_expiry_window_is_wired_from_settings(monkeypatch):
    # A SchedulerConfig field nothing populates from Settings is a knob that
    # silently does nothing — the failure mode this whole issue is about.
    #
    # Asserted against a NON-default value on purpose. Comparing the two
    # defaults passes whether or not the wiring line exists, which is a
    # vacuous test of exactly the thing being checked.
    from core.config import get_settings
    from services.daemon.config import DaemonConfig

    monkeypatch.setenv("DAEMON_APPROVAL_EXPIRY_DAYS", "11")
    get_settings.cache_clear()

    config = DaemonConfig.from_env()
    assert config.scheduler.approval_expiry_days == 11
