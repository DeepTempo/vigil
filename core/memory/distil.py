"""The Distil (#731): a finished hunt becomes Sightings, Verdicts and Gaps.

Poll rather than push. Nothing tells this job that a run ended; it finds
terminals with no marker itself, using the ledger's partial index. That buys
three things a trigger does not: no change to the agent layer, a lost signal
becomes a late write rather than a missing one, and backfill is the same code
path exercised on every tick. Nothing is waiting on it either — memory is read
at the *start* of the next run, so a write that lands an hour later is a write
that lands in time. Memory that waits to be told stops being written the moment
the teller is down.

It maps the harness's already-typed conclusions and never re-derives them. The
fold is TypeScript and a second implementation here would drift while only one
is gated, so a field this job needs and cannot find is a contract change to ask
for. What it reads is ``GET /runs/<id>/distil``.

Idempotency is delete-then-insert, scoped to the investigation, in one
transaction. Not ``ON CONFLICT DO UPDATE``: upserting fixes rows that still
exist and does nothing about rows that should not, so bumping the version on
logic that now yields six Sightings where it yielded eight would leave two stale
rows indistinguishable from real ones. The marker goes in the same transaction —
split them and a crash between either double-writes the investigation or marks
it done when it is not.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from sqlalchemy import delete, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from core.agents.projections import read_distil
from core.memory.entity_keys import entity_key, entity_keys
from core.memory.recall_contract import (
    GapDisposition,
    InvestigationKind,
    Stance,
    Trust,
    VerdictOutcome,
    WindowSource,
)
from core.memory.source_tier import InvestigationKind as TierKind
from core.memory.source_tier import SourceTier, resolve_source_tier
from core.storage.models import (
    EpisodicDistilMarker,
    EpisodicGap,
    EpisodicSighting,
    EpisodicVerdict,
    EpisodicVerdictSource,
)
from core.storage.unit_of_work import unit_of_work

logger = logging.getLogger(__name__)

# Bumped when the mapping below changes what it writes. Re-deriving is
# delete-then-insert, so a bump that now yields fewer rows leaves none behind.
DISTIL_VERSION = 1

# The payload schema this understands. A newer one is refused rather than
# mis-mapped: a field that changed meaning is worse read optimistically than not
# read at all, and the marker's absence brings the investigation back next tick.
SUPPORTED_PAYLOAD_VERSION = 1

# Only hunts are distilled today. A Case closure writes its own Verdict from the
# Case, not from a ledger, and no other run kind concludes anything.
DISTILLED_RUN_KINDS: Tuple[str, ...] = ("hunt",)

DEFAULT_BATCH = 25

# A crash is not an outcome. Nothing an aborted run believed at the moment it
# died is a conclusion, so none of it becomes memory. Running out is different:
# a hunt that spent its budget or found no data still concluded what it
# concluded, and those write normally.
ABORTED = "aborted"
BUDGET_TERMINATED = "budget_terminated"

# Terminals whose ledger this job has not folded at this version. `<>` and not
# `<` because running an older Distil deliberately is a re-derive too.
_CANDIDATES = text(
    """
    SELECT DISTINCT ON (e.run_id) e.run_id AS run_id, e.seq AS seq
    FROM agent_events e
    LEFT JOIN episodic_distil_markers m ON m.origin_run_id = e.run_id
    WHERE e.kind = 'terminal'
      AND e.run_kind = ANY(:kinds)
      AND (m.investigation_id IS NULL OR m.distil_version <> :version OR m.origin_seq < e.seq)
    ORDER BY e.run_id, e.seq DESC
    LIMIT :limit
    """
)


class DistilRefused(RuntimeError):
    """A payload this job will not map. Raised rather than written around."""


def _ts(value: object) -> Optional[datetime]:
    """Parse a harness timestamp, or None when it is absent or unreadable.

    The columns are ``timestamptz``, so a value that arrived without an offset
    is read as UTC rather than as the server's local time — the harness stamps
    in UTC and a naive value here would silently shift by the deployment's zone.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _gap_disposition(status: str, run_outcome: str) -> GapDisposition:
    """Why nothing was gathered for this question.

    ``parked`` is the hunt saying it chose not to pursue this one. Everything
    else is the hunt not getting to it, which is budget when the run ran out of
    budget and plain absence otherwise.
    """
    if status == "parked":
        return GapDisposition.DEPRIORITISED
    if run_outcome == BUDGET_TERMINATED:
        return GapDisposition.BUDGET_EXHAUSTED
    return GapDisposition.NO_EVIDENCE_GATHERED


# Why a Gap exists, when the harness gave no reason of its own. Stated rather
# than left empty: an empty reason reads as a missing field, and these are the
# three known absences.
_GAP_REASONS: Mapping[GapDisposition, str] = {
    GapDisposition.DEPRIORITISED: "parked at the hunt's terminal and never resumed",
    GapDisposition.BUDGET_EXHAUSTED: "the hunt ran out of budget before gathering evidence for it",
    GapDisposition.NO_EVIDENCE_GATHERED: "the hunt ended with no evidence gathered for it",
}


def _outcome_of(status: str) -> Optional[VerdictOutcome]:
    """The Verdict a Hypothesis status becomes, or None when it becomes a Gap.

    ``active`` and ``inconclusive`` are the same case: a claim still standing at
    a terminal did not conclude, and whether that is a Verdict or a Gap is
    decided by whether anything was gathered, not by which of the two it is.
    ``false_positive`` is unreachable here — it arrives only from a Case closure.
    """
    if status in ("proven", "disproven", "handed_off"):
        return VerdictOutcome(status)
    if status in ("inconclusive", "active"):
        return VerdictOutcome.INCONCLUSIVE
    return None


def _sources_of(conclusion: Mapping[str, Any], investigation_id: str) -> List[Dict[str, str]]:
    """Per-source Stance and stamped Source Tier.

    The tier is stamped here and never joined at read time: an integration
    removed or recategorised later must not retroactively change how a past
    Verdict was corroborated. A ``not_evidence`` source is written and logged
    rather than dropped — citing a rule catalogue as corroboration is a defect
    worth being able to see, and a silent drop is a Verdict that looks thinner
    than it is for no recorded reason.
    """
    rows: List[Dict[str, str]] = []
    seen = set()
    for source in conclusion.get("sources") or []:
        system = str(source.get("source_system", "")).strip()
        try:
            stance = Stance(str(source.get("stance", "")).strip())
        except ValueError:
            logger.warning(
                "Distil: %s cites %r with a stance this contract has no value for",
                investigation_id,
                system,
            )
            continue
        if not system or system in seen:
            continue
        seen.add(system)
        tier = resolve_source_tier(system, TierKind.HUNT)
        if tier is SourceTier.NOT_EVIDENCE:
            logger.warning(
                "Distil: %s cites %r on hypothesis %s, which is not evidence",
                investigation_id,
                system,
                conclusion.get("hypothesis_id"),
            )
        rows.append(
            {"source_system": system, "stance": stance.value, "source_tier": tier.value}
        )
    return rows


def _sighting_rows(
    payload: Mapping[str, Any], investigation_id: str, concluded_at: datetime
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for sighting in payload.get("sightings") or []:
        entity = sighting.get("entity") or {}
        key = entity_key(str(entity.get("type", "")), str(entity.get("value", "")))
        first = _ts(sighting.get("first_seen"))
        last = _ts(sighting.get("last_seen"))
        hits = int(sighting.get("hit_count") or 0)
        # A row missing any of these cannot be joined, ordered or counted, and
        # writing a guessed one puts an entity in history it was never in.
        if not key or first is None or last is None or hits <= 0:
            logger.warning("Distil: %s dropped an unusable sighting %r", investigation_id, sighting)
            continue
        rows.append(
            {
                "entity_key": key,
                "investigation_kind": InvestigationKind.HUNT.value,
                "investigation_id": investigation_id,
                "source_system": str(sighting.get("source_system", "")),
                "hit_count": hits,
                "attacker_influenceable": bool(sighting.get("attacker_influenceable")),
                # Both ends inclusive, and ordered: a harness that stamped them
                # out of order would otherwise fail the window constraint and
                # take the whole investigation down with it.
                "first_seen": min(first, last),
                "last_seen": max(first, last),
                "concluded_at": concluded_at,
            }
        )
    return rows


def _conclusion_rows(
    payload: Mapping[str, Any], investigation_id: str, concluded_at: datetime
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split the hunt's conclusions into Verdict rows and Gap rows."""
    run_outcome = str(payload.get("outcome") or "")
    verdicts: List[Dict[str, Any]] = []
    gaps: List[Dict[str, Any]] = []

    for conclusion in payload.get("conclusions") or []:
        hypothesis_id = str(conclusion.get("hypothesis_id", "")).strip()
        if not hypothesis_id:
            logger.warning("Distil: %s has a conclusion with no hypothesis id", investigation_id)
            continue

        status = str(conclusion.get("status", ""))
        subjects = entity_keys(conclusion.get("subject_entities"))
        statement = str(conclusion.get("statement", ""))
        rationale = str(conclusion.get("rationale", ""))
        outcome = _outcome_of(status)
        gathered = int(conclusion.get("evidence_count") or 0) > 0

        # A claim that concluded nothing and gathered nothing is a question the
        # hunt never answered, not a conclusion with an empty outcome. handed_off
        # is never one: it carries evidence, a window and sources, so neither
        # "never looked" nor "failed to conclude" is true of it.
        if outcome is None or (outcome is VerdictOutcome.INCONCLUSIVE and not gathered):
            disposition = _gap_disposition(status, run_outcome)
            gaps.append(
                {
                    "investigation_kind": InvestigationKind.HUNT.value,
                    "investigation_id": investigation_id,
                    "hypothesis_id": hypothesis_id,
                    "statement": statement,
                    "disposition": disposition.value,
                    "reason": rationale or _GAP_REASONS[disposition],
                    "subject_entities": subjects,
                    "concluded_at": concluded_at,
                }
            )
            continue

        first = _ts(conclusion.get("first_seen")) or concluded_at
        last = _ts(conclusion.get("last_seen")) or concluded_at
        verdicts.append(
            {
                "row": {
                    "investigation_kind": InvestigationKind.HUNT.value,
                    "investigation_id": investigation_id,
                    "hypothesis_id": hypothesis_id,
                    "statement": statement,
                    "outcome": outcome.value,
                    "rationale": rationale,
                    "subject_entities": subjects,
                    "attacker_influenceable_only": bool(
                        conclusion.get("attacker_influenceable_only")
                    ),
                    # A hunt is agent-concluded. `analyst` arrives only when a
                    # person closed the Case that authored the Verdict.
                    "trust": Trust.AGENT.value,
                    "first_seen": min(first, last),
                    "last_seen": max(first, last),
                    "window_source": (
                        WindowSource.OBSERVED.value
                        if conclusion.get("window_observed")
                        else WindowSource.ASSERTED.value
                    ),
                    "concluded_at": concluded_at,
                },
                "sources": _sources_of(conclusion, investigation_id),
            }
        )

    return verdicts, gaps


def _clear(session: Session, kind: InvestigationKind, investigation_id: str) -> None:
    """Everything this investigation wrote, scoped to it and to nothing else.

    Verdict sources go with their Verdicts through the foreign key, which is why
    they are not deleted here: deleting them separately would leave a window in
    which a Verdict has none.
    """
    for model in (EpisodicSighting, EpisodicVerdict, EpisodicGap):
        session.execute(
            delete(model).where(
                model.investigation_kind == kind.value,
                model.investigation_id == investigation_id,
            )
        )


def write_distil(session: Session, run_id: str, seq: int, payload: Mapping[str, Any]) -> Dict[str, int]:
    """Map one payload to rows and write them, marker included.

    Everything here is one transaction the caller owns. A failure raises with
    nothing written and no marker, so the investigation comes back next tick
    rather than being recorded as done.
    """
    version = payload.get("distil_schema_version")
    # An absent version is refused rather than read as 0: a payload that does not
    # say what it is could be any shape, and mapping it optimistically writes
    # rows nobody can trust more quietly than writing none.
    if not isinstance(version, int) or version > SUPPORTED_PAYLOAD_VERSION:
        raise DistilRefused(
            f"{run_id} answered distil schema {version!r}; "
            f"this Distil understands {SUPPORTED_PAYLOAD_VERSION}"
        )

    investigation_id = str(payload.get("investigation_id", "")).strip()
    if not investigation_id:
        raise DistilRefused(f"{run_id} answered a distil payload with no investigation id")

    concluded_at = _ts(payload.get("concluded_at"))
    if concluded_at is None:
        raise DistilRefused(f"{run_id} has not concluded, so there is nothing to distil")

    outcome = str(payload.get("outcome") or "")

    # Before the outcome is read, because a re-derive replaces this
    # investigation's rows as a set and an abort is a re-derive that yields none.
    # An outcome is never downgraded once on the record and `aborted` outranks
    # every other, so a hunt that concluded and was later aborted is an
    # investigation whose conclusions are withdrawn — the clear is what withdraws
    # them, and skipping it would leave the old rows reading as current.
    _clear(session, InvestigationKind.HUNT, investigation_id)

    # A crash is not an outcome, so an aborted run contributes no memory. It
    # still takes a marker: the marker records that the investigation was
    # processed, not that it was remembered, and without one this run comes back
    # on every tick forever.
    if outcome == ABORTED:
        counts = {"sightings": 0, "verdicts": 0, "gaps": 0}
    else:
        sightings = _sighting_rows(payload, investigation_id, concluded_at)
        verdicts, gaps = _conclusion_rows(payload, investigation_id, concluded_at)

        session.bulk_insert_mappings(EpisodicSighting, sightings)
        session.bulk_insert_mappings(EpisodicGap, gaps)
        for verdict in verdicts:
            row = EpisodicVerdict(**verdict["row"])
            session.add(row)
            # Flushed for the id its sources reference. One statement per Verdict
            # rather than one for the batch, because a source row cannot name a
            # Verdict that has no id yet.
            session.flush()
            for source in verdict["sources"]:
                session.add(EpisodicVerdictSource(verdict_id=row.id, **source))

        counts = {"sightings": len(sightings), "verdicts": len(verdicts), "gaps": len(gaps)}

    marker = {
        "investigation_kind": InvestigationKind.HUNT.value,
        "investigation_id": investigation_id,
        "origin_run_id": run_id,
        "origin_seq": seq,
        "distil_version": DISTIL_VERSION,
        "sightings_written": counts["sightings"],
        "verdicts_written": counts["verdicts"],
        "gaps_written": counts["gaps"],
        "concluded_at": concluded_at,
    }
    # The one upsert here, and the only row it is right for: a marker is one row
    # keyed by the investigation, so there is no set of stale rows to leave behind.
    # Counts are set from what was just written, never incremented.
    session.execute(
        insert(EpisodicDistilMarker)
        .values(**marker)
        .on_conflict_do_update(
            index_elements=["investigation_kind", "investigation_id"],
            set_={key: marker[key] for key in marker if key not in ("investigation_kind", "investigation_id")}
            | {"distilled_at": text("now()")},
        )
    )
    return counts


def pending(session: Session, limit: int = DEFAULT_BATCH) -> List[Tuple[str, int]]:
    """Terminals with no marker at this version, newest terminal per run."""
    rows = session.execute(
        _CANDIDATES,
        {"kinds": list(DISTILLED_RUN_KINDS), "version": DISTIL_VERSION, "limit": limit},
    ).all()
    return [(str(row.run_id), int(row.seq)) for row in rows]


async def distil_once(limit: int = DEFAULT_BATCH) -> Dict[str, int]:
    """One pass: find terminals, read each fold, write each investigation.

    One transaction per investigation, so a payload this job refuses costs that
    investigation and not the batch. A refusal writes no marker, which is what
    brings it back once the reason is fixed.
    """
    candidates = await asyncio.to_thread(_pending_in_own_session, limit)
    written = {"investigations": 0, "sightings": 0, "verdicts": 0, "gaps": 0, "refused": 0}

    for run_id, seq in candidates:
        payload = await read_distil(run_id)
        if payload is None:
            # Not an error and not a skip-forever: the agent layer may simply be
            # unreachable, and this run is a candidate again next tick.
            logger.debug("Distil: %s had no readable fold", run_id)
            continue
        try:
            counts = await asyncio.to_thread(_write_in_own_session, run_id, seq, payload)
        except DistilRefused as exc:
            logger.warning("Distil refused %s: %s", run_id, exc)
            written["refused"] += 1
            continue
        except Exception:
            # Raised, not swallowed: a write path that swallows is what makes a
            # dead store read as healthy to every surface that reads it.
            logger.exception("Distil failed on %s, leaving neither rows nor marker", run_id)
            written["refused"] += 1
            continue

        written["investigations"] += 1
        for kind in ("sightings", "verdicts", "gaps"):
            written[kind] += counts[kind]

    return written


def _pending_in_own_session(limit: int) -> List[Tuple[str, int]]:
    with unit_of_work() as session:
        return pending(session, limit)


def _write_in_own_session(run_id: str, seq: int, payload: Mapping[str, Any]) -> Dict[str, int]:
    with unit_of_work() as session:
        return write_distil(session, run_id, seq, payload)


__all__: Sequence[str] = (
    "DISTIL_VERSION",
    "DistilRefused",
    "distil_once",
    "pending",
    "write_distil",
)
