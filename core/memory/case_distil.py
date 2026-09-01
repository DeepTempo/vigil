"""The Case Distil (#733): a closed Case becomes a Verdict.

A Case is a Hypothesis, implicitly. Opening one asserts that the activity is
real and malicious; closing it answers that. So the case id is the
``hypothesis_id``, the title is the statement, and the closure category is the
outcome. A closure is a conclusion and not an observation — what was *observed*
were the Case's Findings — so this writes a Verdict and its sources, and never a
Sighting.

**Why this polls state rather than hooking a close.** There is no single
category-bearing close in this codebase. Analysts close by PATCHing ``status``
to ``closed``; the dedicated ``POST /cases/{id}/close`` records a category and
is not what the console calls; the MCP tool closes on its own; ``merge_cases``
closes the source of a merge. A hook on any one of them would miss the path the
issue exists for. Polling the closed *state* catches every writer that exists
and every writer added later, needs no change to any of them, and makes a
re-close or a re-categorised closure a re-derive rather than a duplicate.

The mapping's whole input is the Case: its closure row, its Findings and its
IOCs. Nothing is asked of a model and nothing is extracted from prose. That is
deliberate — the entity extractor lives in the harness (TypeScript) and a second
implementation here would drift while only one is gated, which is the same
argument ``core/memory/distil.py`` makes about the fold.

Idempotency, the marker and the delete-then-insert are shared with the hunt
Distil, and the marker is keyed by investigation rather than by run, which is
what lets a Case take one at all.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.cases.closure import ClosedByKind, ClosureCategory
from core.memory.distil import clear_investigation, write_marker
from core.memory.entity_keys import entity_key
from core.memory.recall_contract import (
    InvestigationKind,
    Stance,
    Trust,
    VerdictOutcome,
    WindowSource,
)
from core.memory.source_tier import InvestigationKind as TierKind
from core.memory.source_tier import SourceTier, resolve_source_tier
from core.storage.models import (
    Case,
    CaseClosureInfo,
    CaseIOC,
    EpisodicVerdict,
    EpisodicVerdictSource,
    Finding,
    case_findings,
)
from core.storage.unit_of_work import unit_of_work

logger = logging.getLogger(__name__)

# Bumped when the mapping below changes what it writes. Separate from the hunt
# Distil's version: re-deriving is delete-then-insert scoped to one
# investigation, and a change to how a Case maps must not re-offer every hunt.
CASE_DISTIL_MAPPING_VERSION = 1

DEFAULT_BATCH = 25

# One retry, then reported. A write that fails twice is a store that is down or
# a Case that is wrong, and neither gets better for being hammered inside a tick
# that comes round again anyway.
ATTEMPTS = 2

# What each closure category concluded. ``duplicate`` is absent on purpose: a
# Case closed as a duplicate concluded nothing about the activity, it said this
# record is the same record as another one. Writing an inconclusive Verdict for
# it would put a claim in memory that nobody made, and writing a proven one
# would count one determination twice.
_OUTCOMES: Mapping[str, VerdictOutcome] = {
    ClosureCategory.RESOLVED.value: VerdictOutcome.PROVEN,
    ClosureCategory.FALSE_POSITIVE.value: VerdictOutcome.FALSE_POSITIVE,
    ClosureCategory.UNABLE_TO_RESOLVE.value: VerdictOutcome.INCONCLUSIVE,
    ClosureCategory.UNSPECIFIED.value: VerdictOutcome.INCONCLUSIVE,
}

# Closed Cases whose Verdict is missing or older than the close. The version is
# matched in the join and not in the filter, so a bump re-offers every Case
# instead of only the ones closed since. ``closed_at`` and ``updated_at`` are
# naive UTC on these tables and ``concluded_at`` is timestamptz, so the close
# instant is cast rather than compared across the two -- an implicit cast would
# read a naive value in the server's zone and silently shift the comparison.
_CANDIDATES = text("""
    SELECT c.case_id AS case_id
    FROM cases c
    LEFT JOIN case_closure_info i ON i.case_id = c.case_id
    LEFT JOIN episodic_distil_markers m
           ON m.investigation_kind = 'case'
          AND m.investigation_id = c.case_id
          AND m.distil_version = :version
    WHERE c.status = 'closed'
      AND (
        m.investigation_id IS NULL
        OR m.concluded_at < (COALESCE(i.closed_at, c.updated_at) AT TIME ZONE 'UTC')
      )
    ORDER BY COALESCE(i.closed_at, c.updated_at) DESC, c.case_id
    LIMIT :limit
    """)


class CaseDistilRefused(RuntimeError):
    """A Case this job will not map. Raised rather than written around."""


@dataclass(frozen=True)
class ClosedCase:
    """One closed Case and everything a Verdict built from it needs.

    Read once, refused once if the Case is not closed, and then carried whole:
    no row can be built from a subset of these, and passing them separately
    invites a caller to build one from the wrong Case's closure.
    """

    case: Case
    closure: Optional[CaseClosureInfo]
    concluded_at: datetime

    @property
    def category(self) -> str:
        """The category the closure recorded, or that none was recorded.

        A Case closed without a closure row -- a status edit that predates the
        console recording one, or ``merge_cases`` -- is not a Case with an
        unknown determination. It is a Case closed with no determination stated,
        which is exactly what ``unspecified`` says.
        """
        if self.closure is None:
            return ClosureCategory.UNSPECIFIED.value
        return (
            self.closure.closure_category or ""
        ).strip() or ClosureCategory.UNSPECIFIED.value

    @property
    def trust(self) -> Trust:
        """Who concluded, from what the close recorded rather than from a name.

        Absent -- a legacy row, or a close that never wrote one -- reads as
        ``agent``. That understates rather than overstates: ``analyst`` is the
        highest-trust record this system produces, and a close nobody can
        attribute has not earned it.
        """
        kind = (self.closure.closed_by_kind if self.closure is not None else "") or ""
        return (
            Trust.ANALYST if kind.strip() == ClosedByKind.ANALYST.value else Trust.AGENT
        )


def _utc(value: Optional[datetime]) -> Optional[datetime]:
    """A naive column value read as the UTC it was written as.

    These tables store naive UTC (``core.time.utcnow``) and the episodic columns
    are ``timestamptz``. Attaching the zone here is what stops a deployment
    outside UTC writing a window shifted by its own offset.
    """
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _rationale(closure: Optional[CaseClosureInfo]) -> str:
    """Why the Case closed, in the order a reader would want it.

    Empty is a known absence rather than a null: the Case was closed without a
    stated reason, which is true, and worth recording as such. A Verdict that
    refused to be written for want of prose would lose the determination too.
    """
    if closure is None:
        return ""
    for candidate in (
        closure.false_positive_reason,
        closure.root_cause,
        closure.executive_summary,
        closure.closure_notes,
    ):
        if candidate and candidate.strip():
            return candidate.strip()
    return ""


def _subjects(session: Session, case_id: str) -> List[str]:
    """The entities the Case names, from its IOCs.

    Not from the title. ADR 0016 draws a Verdict's subjects from its Hypothesis
    statement, extracted with the harness's typed extractor -- which is
    TypeScript, and re-implementing it here is the second implementation that
    drifts while only one is gated. A Case has something the harness has to
    infer: IOCs an analyst attached, already carrying their type.

    That also holds ADR 0016's bound better than the alternatives. IOCs are
    curated, where ``Finding.entity_context`` across a Case's Findings would
    scoop the shared infrastructure the ADR exists to keep off a Verdict.
    """
    rows = (
        session.query(CaseIOC.ioc_type, CaseIOC.value)
        .filter(CaseIOC.case_id == case_id)
        .order_by(CaseIOC.ioc_id)
        .all()
    )
    keys: List[str] = []
    seen = set()
    for ioc_type, value in rows:
        key = entity_key(str(ioc_type or ""), str(value or ""))
        if key and key not in seen:
            seen.add(key)
            keys.append(key)
    return keys


def _window(
    session: Session, closed: ClosedCase
) -> Tuple[datetime, datetime, WindowSource]:
    """When the activity happened, and whether that was observed or asserted.

    A Case's Findings observed it: their ``timestamp`` and ``data_source`` are
    both non-null, so the min and max of them is a real window. A Case with no
    Findings -- a human-created one -- has only its own open and close dates,
    and says so, so that nothing claims precision it does not have. Ranking can
    discount an asserted window, and the error direction is the safe one: it
    reads as recent, so it ranks up rather than disappearing.
    """
    bounds = (
        session.query(Finding.timestamp)
        .join(case_findings, case_findings.c.finding_id == Finding.finding_id)
        .filter(case_findings.c.case_id == closed.case.case_id)
        .all()
    )
    stamps = [stamp for (stamp,) in bounds if stamp is not None]
    if stamps:
        first, last = _utc(min(stamps)), _utc(max(stamps))
        assert first is not None and last is not None
        return first, last, WindowSource.OBSERVED

    opened = _utc(closed.case.created_at) or closed.concluded_at
    return min(opened, closed.concluded_at), closed.concluded_at, WindowSource.ASSERTED


def _sources(session: Session, case_id: str) -> List[Dict[str, str]]:
    """One row per system that produced a Finding on the Case, all supporting.

    Every source takes Stance ``supports`` because the Case asserted the
    activity was real -- that is what grouping those Findings into one claimed.
    Which makes a false-positive closure a clean record of every one of those
    sources having been wrong: the calibration signal, arriving from live
    operation rather than from a backfill.

    The tier is stamped here and never joined at read time, so an integration
    removed or recategorised later cannot retroactively change how a past
    Verdict was corroborated. A ``not_evidence`` source is written and logged
    rather than dropped: a silent drop is a Verdict that looks thinner than it
    is for no recorded reason.
    """
    rows = (
        session.query(Finding.data_source)
        .join(case_findings, case_findings.c.finding_id == Finding.finding_id)
        .filter(case_findings.c.case_id == case_id)
        .distinct()
        .order_by(Finding.data_source)
        .all()
    )
    sources: List[Dict[str, str]] = []
    for (system,) in rows:
        name = str(system or "").strip()
        if not name:
            continue
        tier = resolve_source_tier(name, TierKind.CASE)
        if tier is SourceTier.NOT_EVIDENCE:
            logger.warning(
                "Case Distil: %s cites %r, which is not evidence", case_id, name
            )
        sources.append(
            {
                "source_system": name,
                "stance": Stance.SUPPORTS.value,
                "source_tier": tier.value,
            }
        )
    return sources


def _accept(session: Session, case_id: str) -> ClosedCase:
    """The Case, or a refusal saying what it could not be read on."""
    case = session.get(Case, case_id)
    if case is None:
        raise CaseDistilRefused(f"{case_id} is not a case")
    if (case.status or "").strip() != "closed":
        raise CaseDistilRefused(f"{case_id} is {case.status!r}, not closed")

    closure = session.get(CaseClosureInfo, case_id)
    concluded_at = _utc(closure.closed_at if closure is not None else None) or _utc(
        case.updated_at
    )
    if concluded_at is None:
        raise CaseDistilRefused(
            f"{case_id} is closed but records no instant it closed at"
        )
    return ClosedCase(case, closure, concluded_at)


def write_case_distil(session: Session, case_id: str) -> Dict[str, int]:
    """Map one closed Case to a Verdict and write it, marker included.

    Everything here is one transaction the caller owns. A failure raises with
    nothing written and no marker, so the Case comes back next tick rather than
    being recorded as done.
    """
    closed = _accept(session, case_id)
    kind = InvestigationKind.CASE

    # Before the outcome is decided, and unconditionally: a Case re-closed under
    # a different category -- or re-categorised to duplicate, which writes
    # nothing -- must not leave the earlier Verdict standing beside the new one.
    clear_investigation(session, kind, case_id)

    outcome = _OUTCOMES.get(closed.category)
    if outcome is None:
        if closed.category != ClosureCategory.DUPLICATE.value:
            logger.warning(
                "Case Distil: %s closed as %r, which this mapping has no outcome for",
                case_id,
                closed.category,
            )
        counts = {"verdicts": 0}
    else:
        first, last, window_source = _window(session, closed)
        verdict = EpisodicVerdict(
            investigation_kind=kind.value,
            investigation_id=case_id,
            # A Case is its own Hypothesis, so the two ids are the same string.
            hypothesis_id=case_id,
            statement=closed.case.title or "",
            outcome=outcome.value,
            rationale=_rationale(closed.closure),
            subject_entities=_subjects(session, case_id),
            # A Case's evidence is its Findings, which are our own telemetry,
            # and a Case with none stands on an analyst's assertion. Neither is
            # adversary-authored, which is the thing this flag exists to mark.
            attacker_influenceable_only=False,
            trust=closed.trust.value,
            first_seen=first,
            last_seen=last,
            window_source=window_source.value,
            concluded_at=closed.concluded_at,
        )
        session.add(verdict)
        # Flushed for the id its sources reference: a source row cannot name a
        # Verdict that has no id yet.
        session.flush()
        for source in _sources(session, case_id):
            session.add(EpisodicVerdictSource(verdict_id=verdict.id, **source))
        counts = {"verdicts": 1}

    write_marker(
        session,
        kind=kind,
        investigation_id=case_id,
        version=CASE_DISTIL_MAPPING_VERSION,
        counts=counts,
        concluded_at=closed.concluded_at,
    )
    return counts | {"derived": 1}


def pending(session: Session, limit: int = DEFAULT_BATCH) -> List[str]:
    """Closed Cases no marker at this version covers, newest close first."""
    rows = session.execute(
        _CANDIDATES, {"version": CASE_DISTIL_MAPPING_VERSION, "limit": limit}
    ).all()
    return [str(row.case_id) for row in rows]


async def case_distil_once(limit: int = DEFAULT_BATCH) -> Dict[str, int]:
    """One pass: find closed Cases, write each one's Verdict.

    One transaction per Case, so a Case this job refuses costs that Case and not
    the batch. Nothing is swallowed: a refusal and a failed write are each
    counted and each logged, because a Distil that goes quiet leaves a store
    that reads as healthy and a memory that reads as empty -- and empty is also
    what an entity nobody has looked at reads as. Neither writes a marker, which
    is what brings the Case back once the reason is fixed.
    """
    candidates = await asyncio.to_thread(_pending_in_own_session, limit)
    written = {"cases": 0, "verdicts": 0, "refused": 0, "failed": 0}

    for case_id in candidates:
        counts = await _write_with_retry(case_id, written)
        if counts is None:
            continue
        written["cases"] += counts["derived"]
        written["verdicts"] += counts["verdicts"]

    return written


async def _write_with_retry(
    case_id: str, written: Dict[str, int]
) -> Optional[Dict[str, int]]:
    """One Case's write, retried once. None when it did not land.

    A refusal is not retried: a Case that is not closed will not become closed
    by being read again, and it stops being a candidate on its own.
    """
    for attempt in range(1, ATTEMPTS + 1):
        try:
            return await asyncio.to_thread(_write_in_own_session, case_id)
        except CaseDistilRefused as exc:
            logger.warning("Case Distil refused %s: %s", case_id, exc)
            written["refused"] += 1
            return None
        except Exception:
            if attempt < ATTEMPTS:
                logger.warning(
                    "Case Distil failed on %s, attempt %s of %s; retrying",
                    case_id,
                    attempt,
                    ATTEMPTS,
                )
                continue
            logger.error(
                "Case Distil failed on %s after %s attempts, leaving neither rows nor marker",
                case_id,
                ATTEMPTS,
                exc_info=True,
            )
            written["failed"] += 1
            return None
    return None


def _pending_in_own_session(limit: int) -> List[str]:
    with unit_of_work() as session:
        return pending(session, limit)


def _write_in_own_session(case_id: str) -> Dict[str, int]:
    with unit_of_work() as session:
        return write_case_distil(session, case_id)


__all__: Sequence[str] = (
    "CASE_DISTIL_MAPPING_VERSION",
    "CaseDistilRefused",
    "ClosedCase",
    "case_distil_once",
    "pending",
    "write_case_distil",
)
