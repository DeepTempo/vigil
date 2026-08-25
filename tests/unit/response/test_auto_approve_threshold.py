"""The ``threshold`` on ``should_auto_approve`` has to mean something.

It used to fall back to a literal ``0.85`` after checking the threshold, so
any value above 0.85 was ignored: ``threshold=0.99`` still auto-approved an
action at 0.86. For a parameter whose only purpose is to make the service more
conservative, being inert is the dangerous direction -- an operator raising it
got no error, no warning, and no change in behaviour.

The 0.85 itself was not the defect. It is the bottom of a flag band that
``needs_flag`` and ``get_action_decision`` also draw at 0.85, and actions in
that band are meant to run and be reviewed afterwards. The fix derives the
band from ``threshold`` instead of repeating the literal, so the three agree
by construction and the default behaviour is unchanged.
"""

import pytest

from core.response.approval_service import ApprovalService

MARGIN = ApprovalService.FLAG_MARGIN


@pytest.fixture
def service(monkeypatch):
    svc = ApprovalService.__new__(ApprovalService)
    svc.force_manual_approval = False
    return svc


def action(confidence):
    return {"type": "block_ip", "confidence": confidence}


class TestTheThresholdIsHonoured:
    def test_raising_it_withholds_approval(self):
        # The regression. 0.86 cleared the old hard-coded 0.85 whatever the
        # caller asked for.
        svc = ApprovalService.__new__(ApprovalService)
        svc.force_manual_approval = False
        assert svc.should_auto_approve(action(0.86), threshold=0.99) is False

    def test_lowering_it_grants_approval(self, service):
        assert service.should_auto_approve(action(0.76), threshold=0.80) is True
        assert service.should_auto_approve(action(0.74), threshold=0.80) is False

    def test_the_flag_band_moves_with_it(self, service):
        assert service.should_auto_approve(action(0.94), threshold=0.99) is True
        assert service.should_auto_approve(action(0.93), threshold=0.99) is False

    @pytest.mark.parametrize("threshold", [0.80, 0.90, 0.99])
    def test_the_band_is_always_one_margin_wide(self, service, threshold):
        floor = threshold - MARGIN
        assert service.should_auto_approve(action(floor), threshold=threshold) is True
        assert (
            service.should_auto_approve(action(floor - 0.01), threshold=threshold)
            is False
        )

    def test_the_monitor_line_is_a_floor_the_threshold_cannot_cross(self, service):
        """An action too weak to be worth proposing is not one to carry out
        unattended. Without the clamp, a low threshold would have
        get_action_decision returning monitor_only for something
        should_auto_approve had already cleared."""
        low = ApprovalService.MONITOR_ONLY_BELOW - 0.05
        assert service.should_auto_approve(action(low), threshold=low) is False
        assert (
            service.should_auto_approve(
                action(ApprovalService.MONITOR_ONLY_BELOW), threshold=low
            )
            is True
        )


class TestTheDefaultsAreUnchanged:
    """The shipped behaviour is documented by the existing suite; this pins
    that the change is inert at the default threshold."""

    @pytest.mark.parametrize(
        "confidence,expected",
        [
            (0.95, True),
            (0.90, True),
            (0.87, True),
            (0.85, True),
            (0.84, False),
            (0.75, False),
            (0.55, False),
        ],
    )
    def test_auto_approval(self, service, confidence, expected):
        assert service.should_auto_approve(action(confidence)) is expected

    @pytest.mark.parametrize(
        "confidence,expected",
        [(0.90, False), (0.89, True), (0.85, True), (0.84, False)],
    )
    def test_the_flag_band(self, service, confidence, expected):
        assert service.needs_flag(confidence) is expected

    @pytest.mark.parametrize(
        "confidence,expected",
        [
            (0.95, "auto_approve"),
            (0.85, "auto_approve"),
            (0.84, "manual_approval"),
            (0.70, "manual_approval"),
            (0.69, "monitor_only"),
        ],
    )
    def test_the_decision(self, service, confidence, expected):
        assert service.get_action_decision(action(confidence)) == expected


class TestTheThreeAgree:
    """One constant, so a caller cannot be told two different things about the
    same action."""

    @pytest.mark.parametrize("threshold", [0.60, 0.90, 0.99])
    @pytest.mark.parametrize("confidence", [0.55, 0.72, 0.86, 0.94, 0.99])
    def test_auto_approval_and_the_decision_never_disagree(
        self, service, threshold, confidence
    ):
        approves = service.should_auto_approve(action(confidence), threshold=threshold)
        decision = service.get_action_decision(action(confidence), threshold=threshold)
        if decision == "auto_approve":
            assert approves is True
        else:
            assert approves is False

    def test_a_flagged_action_is_one_that_was_approved(self, service):
        for confidence in (0.85, 0.87, 0.89):
            assert service.needs_flag(confidence) is True
            assert service.should_auto_approve(action(confidence)) is True


class TestForceManualStillWins:
    def test_the_argument(self, service):
        assert (
            service.should_auto_approve(action(0.99), threshold=0.50, force_manual=True)
            is False
        )

    def test_the_service_setting(self, service):
        service.force_manual_approval = True
        assert service.should_auto_approve(action(0.99), threshold=0.50) is False
