"""The RCA-on-handoff gate: a proven threat hunt tees up a root-cause-analysis run
that parks for operator approval; an RCA's own handoff spawns nothing (no loop)."""

from unittest.mock import AsyncMock, Mock, patch

from core.workflows import run_bridge_router as rbr
from core.workflows.run_bridge_router import (
    TerminalHandoff,
    _rca_hypothesis,
    _source_is_hunt,
    _start_root_cause,
)
from core.workflows.workflows_service import _not_a_claim

HANDOFF = TerminalHandoff(
    case_id="case-abc",
    title="IR case case-abc — threat-hunt",
    markdown="The internal host FYODOR-L (192.168.70.186) is beaconing to 45.77.53.176:443.",
)


def _run_service(existing=None):
    """``existing`` is the run row a prior tee-up left, or None when there is none."""
    svc = Mock()
    svc.find_run_by_trigger.return_value = existing
    return svc


def _with_ledger_kind(run_kind, raises=None):
    """Patch the lazily-imported ledger read so it reports run_kind for any run."""
    reader = Mock(side_effect=raises) if raises else Mock(return_value=run_kind)
    return patch("core.workflows.run_resume.run_kind_of", reader)


class TestTheSourceGuard:
    """Answered off the ledger's first event, which is the value the worker itself
    decided to push the handoff early from. The run's workflow row is a different
    question: a hunt started from file paths is filed under 'hunt' rather than
    'threat-hunt', so resolving a definition from it finds nothing."""

    def test_a_threat_hunt_source_is_a_hunt(self):
        with _with_ledger_kind("hunt"):
            assert _source_is_hunt("run-1") is True

    def test_a_root_cause_source_is_not_a_hunt(self):
        # An RCA's own handoff must not spawn another RCA.
        with _with_ledger_kind("root_cause"):
            assert _source_is_hunt("run-2") is False

    def test_a_run_with_no_ledger_is_not_a_hunt(self):
        with _with_ledger_kind(None):
            assert _source_is_hunt("run-3") is False

    def test_an_unreadable_ledger_is_not_a_hunt(self):
        with _with_ledger_kind(None, raises=RuntimeError("db gone")):
            assert _source_is_hunt("run-4") is False


class TestTeeingUpTheRootCause:
    def test_a_hunt_handoff_enqueues_exactly_one_rca_with_a_derived_hypothesis(self):
        # _process_handoff owns the dedup guard, so _start_root_cause is the sole
        # tee-up and takes no run_service of its own.
        enqueue = AsyncMock(return_value={"success": True, "run_id": "r-1"})
        with patch.object(rbr, "_enqueue_root_cause", enqueue):
            _start_root_cause("run-1", HANDOFF, "case-opened")

        enqueue.assert_awaited_once()
        params, triggered_by = enqueue.await_args.args
        assert triggered_by == "handoff:run-1:case-abc"
        # Only what the run reads. agent_id and source_run_id used to ride along
        # here unconsumed — the roster is rootcause.yaml's, and triggered_by above
        # already carries which run this traces back from.
        assert set(params) == {"hypothesis", "context", "case_id"}
        # Ties the backward claim to the escalation it traces back from. The host is
        # deliberately not named: nothing here knows which one it is, and the finding
        # travels verbatim in context, where the run reads it on turn 0.
        assert "case-abc" in params["hypothesis"]
        assert "FYODOR-L" in params["context"]
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

    def test_a_second_arrival_tees_no_second_rca(self):
        # The /handoff push already teed the RCA; the terminal re-carries the same
        # handoff and must tee nothing further. _open_case is still called -- it
        # keys on the handoff and finds the case the first arrival opened, which is
        # its own gate rather than this one's.
        svc = _run_service(existing={"run_id": "r-1", "status": "running"})
        with patch.object(rbr, "_open_case", return_value="case-opened"), patch.object(
            rbr, "_start_root_cause"
        ) as start_rca:
            rbr._process_handoff("run-1", HANDOFF, "", True, svc)
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


def test_the_hypothesis_names_the_escalation_and_never_a_host():
    # The case file is the rendered document, payload JSON and all. Nothing in it is
    # a subject this side can pick out: a hash algorithm, a CVE or a cloud region
    # reads exactly like a hostname, and the C2 address reads exactly like the
    # victim's. So the claim is stated about the compromise, not about a machine.
    noisy = TerminalHandoff(
        case_id="case-x",
        title="Exploitation of CVE-2024-21412 confirmed",
        markdown="payload SHA-256: 9f2c… in region US-EAST-1, egress to 45.77.53.176",
    )
    h = _rca_hypothesis(noisy)
    assert "case-x" in h
    assert "patient zero" in h
    for guess in ("CVE-2024", "SHA-256", "US-EAST", "45.77.53.176"):
        assert guess not in h

    # And it is still a claim a run can argue against, which _nothing_to_run checks
    # before the run is allowed to start.
    assert not _not_a_claim(h)
