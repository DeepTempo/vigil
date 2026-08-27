"""An approval nobody will ever answer ages out instead of sitting pending.

`withdraw_for_run` closes the questions an ended run left open, but it keys on
`workflow_run_id`, so approvals raised without a run behind them are
unreachable — nothing ages them out and the pending queue only grows (#675).
A containment action proposed weeks ago is also not safe to approve out of a
cluttered queue: the reason it was raised has stopped being true.
"""

from datetime import timedelta
from types import SimpleNamespace

import pytest

from core.response.checkpoints import expire_stale
from core.time import utcnow


class FakeApprovals:
    def __init__(self, stale_ids):
        self.stale_ids = list(stale_ids)
        self.rejected = []
        self.asked_cutoff = None

    def list_stale_pending(self, cutoff):
        self.asked_cutoff = cutoff
        return list(self.stale_ids)

    def reject_action(self, action_id, reason, rejected_by="analyst"):
        self.rejected.append((action_id, reason, rejected_by))
        return SimpleNamespace(action_id=action_id)


@pytest.mark.unit
def test_expires_every_approval_past_the_window():
    approvals = FakeApprovals(["a", "b", "c"])

    assert expire_stale(7, approvals) == 3
    assert [one[0] for one in approvals.rejected] == ["a", "b", "c"]


@pytest.mark.unit
def test_attributes_the_expiry_to_the_sweep_not_to_a_human():
    # The audit trail has to distinguish "the system aged this out" from "an
    # analyst said no"; approved_by carries that, so it must not say "analyst".
    approvals = FakeApprovals(["a"])

    expire_stale(7, approvals)
    action_id, reason, rejected_by = approvals.rejected[0]
    assert rejected_by == "system"
    assert "7" in reason and "expired" in reason.lower()


@pytest.mark.unit
def test_cutoff_is_the_window_before_now():
    approvals = FakeApprovals([])
    before = utcnow()

    expire_stale(7, approvals)

    after = utcnow()
    # Bracketed rather than compared to a fixed instant, so the assertion does
    # not depend on how long the call took.
    assert before - timedelta(days=7) <= approvals.asked_cutoff
    assert approvals.asked_cutoff <= after - timedelta(days=7)


@pytest.mark.unit
def test_rejects_nothing_when_the_queue_is_current():
    approvals = FakeApprovals([])

    assert expire_stale(7, approvals) == 0
    assert approvals.rejected == []


@pytest.mark.unit
def test_a_zero_or_negative_window_is_refused():
    # A window of 0 would expire approvals raised seconds ago, including the one
    # an operator is looking at. Misconfiguration should not silently empty the
    # queue.
    approvals = FakeApprovals(["a"])

    with pytest.raises(ValueError):
        expire_stale(0, approvals)
    assert approvals.rejected == []
