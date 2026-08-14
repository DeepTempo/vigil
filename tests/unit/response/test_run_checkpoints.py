"""An ended run withdraws the questions nobody answered.

Nothing did, so the approvals queue filled with questions whose run was long
over and a real one was buried among them.
"""

from types import SimpleNamespace

import pytest

from core.response.checkpoints import withdraw_for_run


class FakeApprovals:
    def __init__(self, open_ids):
        self.open_ids = list(open_ids)
        self.rejected = []
        self.asked_for = None

    def list_actions(self, status=None, workflow_run_id=None):
        self.asked_for = (status, workflow_run_id)
        return [SimpleNamespace(action_id=one) for one in self.open_ids]

    def reject_action(self, action_id, reason, rejected_by="analyst"):
        self.rejected.append((action_id, reason, rejected_by))
        return None


@pytest.mark.unit
def test_withdraws_every_question_the_run_left_open():
    approvals = FakeApprovals(["a", "b"])

    assert withdraw_for_run("run-1", "the run was abandoned", approvals) == 2
    assert [one[0] for one in approvals.rejected] == ["a", "b"]
    # Attributed to the layer that withdrew it, not to whoever never answered.
    assert approvals.rejected[0][1:] == ("the run was abandoned", "agent")


@pytest.mark.unit
def test_asks_only_for_this_run_and_only_for_open_questions():
    approvals = FakeApprovals([])

    assert withdraw_for_run("run-1", "ended", approvals) == 0
    status, run_id = approvals.asked_for
    assert run_id == "run-1"
    assert status.value == "pending"
