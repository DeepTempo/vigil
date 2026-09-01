"""Closing a Case writes a Verdict (#733), against real rows and a real Postgres.

The mapping is only half of what matters here. The other half is the poll, which
is a SQL predicate over three tables with a timestamptz on one side and naive UTC
on the other, and the idempotency, which is delete-then-insert against a marker
whose CHECK ties its shape to the investigation kind. A fake would agree with
whatever this module happened to do.

Cases are built the way the console and the close path build them, not through
the API, because what is asserted is the Distil and not the router.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from core.cases.closure import ClosedByKind, ClosureCategory
from core.memory.case_distil import (
    CASE_DISTIL_MAPPING_VERSION,
    CaseDistilRefused,
    pending,
    write_case_distil,
)
from core.memory.recall import recall_entity
from core.storage.connection import get_db_session
from core.storage.models import (
    Case,
    CaseClosureInfo,
    CaseIOC,
    EpisodicDistilMarker,
    EpisodicGap,
    EpisodicReadLog,
    EpisodicSighting,
    EpisodicVerdict,
    EpisodicVerdictSource,
    Finding,
    case_findings,
)

pytestmark = [pytest.mark.unit, pytest.mark.database, pytest.mark.external_service]

# Naive, because that is what these tables store: `core.time.utcnow` writes the
# UTC wall clock without a zone, and the Distil is what attaches one.
OPENED = datetime(2026, 8, 1, 9, 0, 0)
CLOSED = datetime(2026, 8, 3, 17, 0, 0)


@pytest.fixture
def session():
    """A session on the throwaway database, emptied of what these tests write.

    Ordering between tests is arbitrary and several of these read whole tables,
    so each starts from nothing rather than filtering its own rows out.
    """
    db = get_db_session()
    try:
        _empty(db)
        yield db
    finally:
        db.rollback()
        _empty(db)
        db.close()


def _empty(db):
    db.execute(case_findings.delete())
    for model in (
        EpisodicVerdictSource,
        EpisodicVerdict,
        EpisodicSighting,
        EpisodicGap,
        EpisodicReadLog,
        EpisodicDistilMarker,
        CaseIOC,
        CaseClosureInfo,
        Case,
    ):
        db.query(model).delete()
    db.query(Finding).filter(Finding.finding_id.like("f-733-%")).delete(
        synchronize_session=False
    )
    db.commit()


def case(
    db,
    case_id="case-733",
    *,
    status="closed",
    title="beaconing from 10.1.2.3 to evil.example.com",
    opened=OPENED,
    updated=CLOSED,
):
    row = Case(
        case_id=case_id,
        title=title,
        description="",
        status=status,
        priority="high",
        created_at=opened,
        updated_at=updated,
    )
    db.add(row)
    db.flush()
    return row


def closure(
    db,
    case_id="case-733",
    *,
    category=ClosureCategory.FALSE_POSITIVE.value,
    kind=ClosedByKind.ANALYST.value,
    closed_by="nestor",
    closed_at=CLOSED,
    **fields,
):
    row = CaseClosureInfo(
        case_id=case_id,
        closure_category=category,
        closed_by=closed_by,
        closed_by_kind=kind,
        closed_at=closed_at,
        **fields,
    )
    db.add(row)
    db.flush()
    return row


def ioc(db, ioc_type, value, *, case_id="case-733"):
    row = CaseIOC(case_id=case_id, ioc_type=ioc_type, value=value)
    db.add(row)
    db.flush()
    return row


def finding(db, finding_id, *, case_id="case-733", when, source="loglm"):
    row = Finding(
        finding_id=finding_id,
        embedding=[0.0] * 768,
        mitre_predictions={},
        anomaly_score=0.5,
        timestamp=when,
        data_source=source,
    )
    db.add(row)
    db.flush()
    db.execute(case_findings.insert().values(case_id=case_id, finding_id=finding_id))
    return row


def verdicts(db, case_id="case-733"):
    return (
        db.query(EpisodicVerdict)
        .filter_by(investigation_kind="case", investigation_id=case_id)
        .all()
    )


def sources(db, verdict):
    return (
        db.query(EpisodicVerdictSource)
        .filter_by(verdict_id=verdict.id)
        .order_by(EpisodicVerdictSource.source_system)
        .all()
    )


class TestWhatAClosureWrites:
    def test_a_closed_case_writes_a_verdict_and_its_sources_and_no_sightings(
        self, session
    ):
        case(session)
        closure(session)
        finding(session, "f-733-a", when=datetime(2026, 8, 1, 10, 0), source="loglm")
        finding(session, "f-733-b", when=datetime(2026, 8, 2, 11, 0), source="firewall")

        counts = write_case_distil(session, "case-733")

        assert counts == {"verdicts": 1, "derived": 1}
        (row,) = verdicts(session)
        assert row.hypothesis_id == "case-733"
        assert row.statement == "beaconing from 10.1.2.3 to evil.example.com"
        assert {s.source_system for s in sources(session, row)} == {"loglm", "firewall"}
        # A closure is a conclusion, not an observation. What was observed were
        # the Case's Findings, and those are not this writer's to record.
        assert session.query(EpisodicSighting).count() == 0
        assert session.query(EpisodicGap).count() == 0

    def test_every_source_supports_because_the_case_asserted_the_activity_was_real(
        self, session
    ):
        case(session)
        closure(session, category=ClosureCategory.FALSE_POSITIVE.value)
        finding(session, "f-733-a", when=datetime(2026, 8, 1, 10, 0), source="loglm")
        finding(session, "f-733-b", when=datetime(2026, 8, 2, 11, 0), source="edr")

        write_case_distil(session, "case-733")

        (row,) = verdicts(session)
        # Which is what makes a false-positive closure the calibration signal:
        # every one of these sources supported a claim that turned out wrong.
        assert row.outcome == "false_positive"
        assert [s.stance for s in sources(session, row)] == ["supports", "supports"]

    def test_the_source_tier_is_stamped_at_write_time(self, session):
        case(session)
        closure(session)
        finding(session, "f-733-a", when=datetime(2026, 8, 1, 10, 0), source="loglm")

        write_case_distil(session, "case-733")

        (row,) = verdicts(session)
        assert [s.source_tier for s in sources(session, row)] == ["telemetry"]

    def test_a_case_with_no_findings_writes_a_verdict_with_no_sources(self, session):
        case(session)
        closure(session)

        write_case_distil(session, "case-733")

        (row,) = verdicts(session)
        assert sources(session, row) == []


class TestCategoryMapping:
    @pytest.mark.parametrize(
        "category,outcome",
        [
            (ClosureCategory.RESOLVED.value, "proven"),
            (ClosureCategory.FALSE_POSITIVE.value, "false_positive"),
            (ClosureCategory.UNABLE_TO_RESOLVE.value, "inconclusive"),
            (ClosureCategory.UNSPECIFIED.value, "inconclusive"),
        ],
    )
    def test_each_category_maps(self, session, category, outcome):
        case(session)
        closure(session, category=category)

        write_case_distil(session, "case-733")

        (row,) = verdicts(session)
        assert row.outcome == outcome

    def test_duplicate_writes_no_verdict_but_still_takes_a_marker(self, session):
        case(session)
        closure(session, category=ClosureCategory.DUPLICATE.value)

        counts = write_case_distil(session, "case-733")

        # A duplicate concluded nothing about the activity; it said this record
        # is that record. The marker records that the Case was processed, not
        # that it was remembered -- without one it comes back on every tick.
        assert counts == {"verdicts": 0, "derived": 1}
        assert verdicts(session) == []
        assert session.get(EpisodicDistilMarker, ("case", "case-733")) is not None

    def test_a_category_this_mapping_does_not_know_writes_nothing(self, session):
        case(session)
        closure(session, category="escalated_to_legal")

        counts = write_case_distil(session, "case-733")

        assert counts == {"verdicts": 0, "derived": 1}
        assert verdicts(session) == []

    def test_a_close_with_no_closure_row_reads_as_unspecified(self, session):
        # How merge_cases closed before #733, and how anything writing the
        # status column directly still closes.
        case(session)

        write_case_distil(session, "case-733")

        (row,) = verdicts(session)
        assert row.outcome == "inconclusive"
        assert row.rationale == ""


class TestTrust:
    def test_a_case_closed_by_a_person_carries_analyst(self, session):
        case(session)
        closure(session, kind=ClosedByKind.ANALYST.value)

        write_case_distil(session, "case-733")

        assert verdicts(session)[0].trust == "analyst"

    def test_a_case_closed_by_an_agent_carries_agent(self, session):
        case(session)
        closure(session, kind=ClosedByKind.AGENT.value)

        write_case_distil(session, "case-733")

        assert verdicts(session)[0].trust == "agent"

    def test_a_close_that_recorded_no_actor_understates_rather_than_overstates(
        self, session
    ):
        case(session)

        write_case_distil(session, "case-733")

        assert verdicts(session)[0].trust == "agent"


class TestWindow:
    def test_a_case_with_findings_takes_its_window_from_them(self, session):
        case(session)
        closure(session)
        finding(session, "f-733-a", when=datetime(2026, 8, 1, 10, 0))
        finding(session, "f-733-b", when=datetime(2026, 8, 2, 11, 30))
        finding(session, "f-733-c", when=datetime(2026, 7, 31, 8, 0))

        write_case_distil(session, "case-733")

        (row,) = verdicts(session)
        assert row.window_source == "observed"
        assert row.first_seen == datetime(2026, 7, 31, 8, 0, tzinfo=timezone.utc)
        assert row.last_seen == datetime(2026, 8, 2, 11, 30, tzinfo=timezone.utc)

    def test_a_case_with_no_findings_asserts_its_own_dates(self, session):
        case(session)
        closure(session)

        write_case_distil(session, "case-733")

        (row,) = verdicts(session)
        assert row.window_source == "asserted"
        assert row.first_seen == OPENED.replace(tzinfo=timezone.utc)
        assert row.last_seen == CLOSED.replace(tzinfo=timezone.utc)

    def test_a_naive_column_is_read_as_the_utc_it_was_written_as(self, session):
        case(session)
        closure(session)
        finding(session, "f-733-a", when=datetime(2026, 8, 1, 10, 0))

        write_case_distil(session, "case-733")

        (row,) = verdicts(session)
        # Not shifted by the deployment's zone, which is the failure this would
        # have: naive in, UTC out, and the window still names the same instant.
        assert row.first_seen == datetime(2026, 8, 1, 10, 0, tzinfo=timezone.utc)


class TestRationale:
    def test_it_falls_back_through_the_four_fields_in_order(self, session):
        case(session)
        closure(
            session,
            false_positive_reason="the scanner is ours",
            root_cause="internal vulnerability scan",
            executive_summary="benign",
            closure_notes="see ticket",
        )

        write_case_distil(session, "case-733")

        assert verdicts(session)[0].rationale == "the scanner is ours"

    @pytest.mark.parametrize(
        "fields,expected",
        [
            ({"root_cause": "internal scan"}, "internal scan"),
            ({"executive_summary": "benign"}, "benign"),
            ({"closure_notes": "see ticket"}, "see ticket"),
        ],
    )
    def test_each_later_field_is_reachable(self, session, fields, expected):
        case(session)
        closure(session, **fields)

        write_case_distil(session, "case-733")

        assert verdicts(session)[0].rationale == expected

    def test_a_close_with_no_stated_reason_writes_an_empty_rationale(self, session):
        case(session)
        closure(session)

        write_case_distil(session, "case-733")

        # Empty is a known absence, not a null, and not a reason to refuse the
        # determination: the Case closed, and that is the record worth keeping.
        assert verdicts(session)[0].rationale == ""


class TestSubjects:
    def test_the_verdict_names_the_case_s_iocs(self, session):
        case(session)
        closure(session)
        ioc(session, "ip", "10.1.2.3")
        ioc(session, "domain", "EVIL.example.com")

        write_case_distil(session, "case-733")

        assert verdicts(session)[0].subject_entities == [
            "ip:10.1.2.3",
            "domain:evil.example.com",
        ]

    def test_defanged_indicators_are_minted_as_the_reader_queries_them(self, session):
        case(session)
        closure(session)
        ioc(session, "domain", "evil[.]example[.]com")

        write_case_distil(session, "case-733")

        assert verdicts(session)[0].subject_entities == ["domain:evil.example.com"]

    def test_a_case_with_no_iocs_names_nothing_rather_than_failing(self, session):
        case(session)
        closure(session)

        write_case_distil(session, "case-733")

        assert verdicts(session)[0].subject_entities == []

    def test_an_unusable_ioc_is_dropped_and_the_rest_survive(self, session):
        case(session)
        closure(session)
        ioc(session, "", "10.1.2.3")
        ioc(session, "ip", "10.9.9.9")

        write_case_distil(session, "case-733")

        assert verdicts(session)[0].subject_entities == ["ip:10.9.9.9"]


class TestThePoll:
    def test_a_closed_case_with_no_marker_is_a_candidate(self, session):
        case(session)
        closure(session)

        assert pending(session) == ["case-733"]

    def test_an_open_case_is_not(self, session):
        case(session, status="investigating")

        assert pending(session) == []

    def test_a_case_already_distilled_is_not_offered_again(self, session):
        case(session)
        closure(session)
        write_case_distil(session, "case-733")
        session.commit()

        assert pending(session) == []

    def test_a_case_closed_again_later_comes_back(self, session):
        case(session)
        closure(session)
        write_case_distil(session, "case-733")
        session.commit()

        session.get(CaseClosureInfo, "case-733").closed_at = CLOSED + timedelta(days=1)
        session.commit()

        assert pending(session) == ["case-733"]

    def test_a_version_bump_re_offers_every_case(self, session, monkeypatch):
        case(session)
        closure(session)
        write_case_distil(session, "case-733")
        session.commit()

        monkeypatch.setattr(
            "core.memory.case_distil.CASE_DISTIL_MAPPING_VERSION",
            CASE_DISTIL_MAPPING_VERSION + 1,
        )
        assert pending(session) == ["case-733"]

    def test_a_case_with_no_closure_row_is_offered_on_its_updated_at(self, session):
        case(session, updated=CLOSED)

        assert pending(session) == ["case-733"]


class TestIdempotency:
    def test_writing_twice_leaves_one_verdict(self, session):
        case(session)
        closure(session)
        finding(session, "f-733-a", when=datetime(2026, 8, 1, 10, 0))

        write_case_distil(session, "case-733")
        write_case_distil(session, "case-733")

        (row,) = verdicts(session)
        assert len(sources(session, row)) == 1

    def test_re_closing_under_a_new_category_replaces_the_verdict(self, session):
        case(session)
        closure(session, category=ClosureCategory.RESOLVED.value)
        write_case_distil(session, "case-733")

        session.get(CaseClosureInfo, "case-733").closure_category = (
            ClosureCategory.FALSE_POSITIVE.value
        )
        write_case_distil(session, "case-733")

        (row,) = verdicts(session)
        assert row.outcome == "false_positive"

    def test_re_categorising_to_duplicate_withdraws_the_verdict(self, session):
        case(session)
        closure(session, category=ClosureCategory.RESOLVED.value)
        write_case_distil(session, "case-733")

        session.get(CaseClosureInfo, "case-733").closure_category = (
            ClosureCategory.DUPLICATE.value
        )
        write_case_distil(session, "case-733")

        # The clear runs before the outcome is decided, so a category that
        # writes nothing does not leave the earlier Verdict standing.
        assert verdicts(session) == []

    def test_the_marker_records_a_case_that_was_never_run(self, session):
        case(session)
        closure(session)

        write_case_distil(session, "case-733")

        marker = session.get(EpisodicDistilMarker, ("case", "case-733"))
        assert marker.origin_run_id is None
        assert marker.origin_seq is None
        assert marker.origin_run_ids == []
        assert marker.verdicts_written == 1


class TestRefusal:
    def test_a_case_that_is_not_closed_is_refused(self, session):
        case(session, status="open")

        with pytest.raises(CaseDistilRefused):
            write_case_distil(session, "case-733")

    def test_a_case_that_does_not_exist_is_refused(self, session):
        with pytest.raises(CaseDistilRefused):
            write_case_distil(session, "case-nothing")

    def test_a_refusal_leaves_no_marker(self, session):
        case(session, status="open")

        with pytest.raises(CaseDistilRefused):
            write_case_distil(session, "case-733")

        assert session.get(EpisodicDistilMarker, ("case", "case-733")) is None


class TestRecall:
    def test_a_case_derived_verdict_is_returned_for_the_entities_it_names(
        self, session
    ):
        case(session)
        closure(session, category=ClosureCategory.FALSE_POSITIVE.value)
        ioc(session, "ip", "10.1.2.3")
        finding(session, "f-733-a", when=datetime(2026, 8, 1, 10, 0))
        write_case_distil(session, "case-733")
        session.commit()

        result = recall_entity(
            {
                "entity_keys": ["ip:10.1.2.3"],
                "as_of": (CLOSED + timedelta(days=1))
                .replace(tzinfo=timezone.utc)
                .isoformat(),
                "caller_kind": "test",
                "caller_id": "test-case-distil",
            }
        )

        found = result["verdicts"]
        assert [v["investigation_id"] for v in found] == ["case-733"]
        assert found[0]["outcome"] == "false_positive"
        assert found[0]["trust"] == "analyst"

    def test_an_entity_the_case_does_not_name_does_not_reach_it(self, session):
        case(session)
        closure(session)
        ioc(session, "ip", "10.1.2.3")
        write_case_distil(session, "case-733")
        session.commit()

        result = recall_entity(
            {
                "entity_keys": ["ip:192.0.2.9"],
                "as_of": (CLOSED + timedelta(days=1))
                .replace(tzinfo=timezone.utc)
                .isoformat(),
                "caller_kind": "test",
                "caller_id": "test-case-distil",
            }
        )

        assert result["verdicts"] == []


class TestMerge:
    """A merge closes the source, and what it concluded is `duplicate`."""

    def test_merging_records_a_duplicate_closure_so_no_verdict_is_minted(self, session):
        from core.cases.case_workflow_service import CaseWorkflowService

        case(session, "case-733")
        case(session, "case-733-dup", title="the same beaconing, filed twice")
        session.commit()

        CaseWorkflowService().merge_cases(
            "case-733", "case-733-dup", merged_by="nestor"
        )

        session.expire_all()
        recorded = session.get(CaseClosureInfo, "case-733-dup")
        assert recorded.closure_category == ClosureCategory.DUPLICATE.value
        assert recorded.closed_by_kind == ClosedByKind.AGENT.value

        # Without the closure row the merge would read as a close with no reason
        # stated, minting an inconclusive Verdict for a Case that concluded
        # nothing and counting the target's determination twice.
        counts = write_case_distil(session, "case-733-dup")
        assert counts["verdicts"] == 0
        assert verdicts(session, "case-733-dup") == []
