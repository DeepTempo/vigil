"""The RCA-on-handoff gate: a proven threat hunt tees up a root-cause-analysis run
that parks for operator approval; an RCA's own handoff spawns nothing (no loop)."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from core.workflows import run_bridge_router as rbr
from core.workflows.run_bridge_router import (
    TerminalHandoff,
    _rca_hypothesis,
    _source_is_hunt,
    _start_root_cause,
)

HANDOFF = TerminalHandoff(
    case_id="case-abc",
    title="IR case case-abc — threat-hunt",
    markdown="The internal host FYODOR-L (192.168.70.186) is beaconing to 45.77.53.176:443.",
)


def _run_service(existing=None):
    svc = Mock()
    svc.list_runs.return_value = existing or []
    return svc


def _with_workflow(run_kind):
    """Patch the lazily-imported WorkflowsService so get_workflow reports run_kind."""
    ws = Mock()
    ws.return_value.get_workflow.return_value = SimpleNamespace(run_kind=run_kind)
    return patch("core.workflows.workflows_service.WorkflowsService", ws)


class TestTheSourceGuard:
    def test_a_threat_hunt_source_is_a_hunt(self):
        svc = Mock()
        svc.get_run.return_value = {"workflow_id": "threat-hunt"}
        with _with_workflow("hunt"):
            assert _source_is_hunt("run-1", svc) is True

    def test_a_root_cause_source_is_not_a_hunt(self):
        # An RCA's own handoff must not spawn another RCA.
        svc = Mock()
        svc.get_run.return_value = {"workflow_id": "root-cause-analysis"}
        with _with_workflow("root_cause"):
            assert _source_is_hunt("run-2", svc) is False

    def test_unknown_run_is_not_a_hunt(self):
        svc = Mock()
        svc.get_run.return_value = None
        assert _source_is_hunt("run-3", svc) is False


class TestTeeingUpTheRootCause:
    def test_a_hunt_handoff_enqueues_exactly_one_rca_with_a_derived_hypothesis(self):
        # _process_handoff owns the dedup guard, so _start_root_cause is the sole
        # tee-up and takes no run_service of its own.
        enqueue = AsyncMock()
        with patch.object(rbr, "_enqueue_root_cause", enqueue):
            _start_root_cause("run-1", HANDOFF, "case-opened")

        enqueue.assert_awaited_once()
        params, triggered_by = enqueue.await_args.args
        assert triggered_by == "handoff:run-1:case-abc"
        assert params["agent_id"] == "threat_hunter"
        # Derived from the handoff finding, naming the confirmed host.
        assert "FYODOR-L" in params["hypothesis"]
        assert "case-abc" in params["hypothesis"]
        # No approve_hypotheses pinned, so the workflow's ask checkpoint governs.
        assert "approve_hypotheses" not in params
        # Files back onto the IR case the hunt opened.
        assert params["case_id"] == "case-opened"


class TestProcessHandoff:
    """A handoff is filed the moment it lands and again on the terminal that carries
    it, so processing one must open its case and tee its RCA exactly once."""

    def test_a_hunt_handoff_opens_a_case_and_tees_the_rca(self):
        svc = _run_service()
        with patch.object(rbr, "_open_case", return_value="case-opened") as open_case, patch.object(
            rbr, "_start_root_cause"
        ) as start_rca:
            rbr._process_handoff("run-1", HANDOFF, "", True, svc)
        open_case.assert_called_once()
        start_rca.assert_called_once()
        # The RCA is teed onto the case that was just opened, not the agent-side id.
        assert start_rca.call_args.args[2] == "case-opened"

    def test_a_second_arrival_opens_no_new_case(self):
        # The /handoff push already teed the RCA; the terminal re-carries the same
        # handoff and must be a no-op, not a duplicate case.
        already = [{"triggered_by": "handoff:run-1:case-abc"}]
        svc = _run_service(existing=already)
        with patch.object(rbr, "_open_case") as open_case, patch.object(
            rbr, "_start_root_cause"
        ) as start_rca:
            rbr._process_handoff("run-1", HANDOFF, "", True, svc)
        open_case.assert_not_called()
        start_rca.assert_not_called()

    def test_a_non_hunt_handoff_opens_a_case_but_tees_nothing(self):
        # A root-cause run's own handoff opens its case and spawns no further RCA.
        svc = _run_service()
        with patch.object(rbr, "_open_case", return_value="case-opened") as open_case, patch.object(
            rbr, "_start_root_cause"
        ) as start_rca:
            rbr._process_handoff("run-2", HANDOFF, "", False, svc)
        open_case.assert_called_once()
        start_rca.assert_not_called()


def test_hypothesis_falls_back_without_a_host():
    bare = TerminalHandoff(case_id="case-x", title="a finding", markdown="")
    h = _rca_hypothesis(bare)
    assert "case-x" in h
    assert "patient zero" in h
