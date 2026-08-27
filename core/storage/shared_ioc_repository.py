"""Repository for ``shared_iocs`` — the cross-investigation IOC index.

An indicator is addressed by a *key*: ``"<ioc_type>:<value>"`` with both halves
stripped and lower-cased. That is the form the daemon's correlation code passes
around; the two halves are stored in separate columns so ``idx_shared_ioc_value``
can serve the overlap join.

Operates on a caller-provided ``Session`` (wrap it with
``core.storage.unit_of_work.unit_of_work`` or ``session_scope``); it never opens
or closes sessions itself.
"""

import logging
from typing import Iterable, List, Optional, Set, Tuple

from sqlalchemy import ColumnElement, and_, or_, select
from sqlalchemy.orm import Session

from core.storage.models import CaseIOC, Investigation, SharedIOC

logger = logging.getLogger(__name__)

# An investigation in one of these statuses is finished: nothing more will be
# added to it, so a new finding touching its indicators is related history
# rather than a duplicate of work in flight.
CLOSED_STATUSES = ("completed", "failed")

# Mirrors the column widths on SharedIOC. A value that does not fit is dropped
# rather than truncated: a truncated indicator would join against unrelated ones.
_MAX_TYPE_LEN = 30
_MAX_VALUE_LEN = 500


def make_key(ioc_type: Optional[str], value: Optional[str]) -> Optional[str]:
    """Build a lookup key, or ``None`` if either half is empty or oversized."""
    ioc_type = (ioc_type or "").strip().lower()
    value = (value or "").strip().lower()
    if not ioc_type or not value:
        return None
    if len(ioc_type) > _MAX_TYPE_LEN or len(value) > _MAX_VALUE_LEN:
        logger.debug("Dropping oversized IOC key %s:%.40s...", ioc_type, value)
        return None
    return f"{ioc_type}:{value}"


def split_key(key: str) -> Optional[Tuple[str, str]]:
    """Split a key back into ``(ioc_type, value)``.

    Only the first colon separates — an IPv6 address is all colons after that.
    """
    ioc_type, sep, value = (key or "").partition(":")
    if not sep or not ioc_type or not value:
        return None
    return ioc_type, value


def index_case_iocs_on_close(session: Session, case_id: str) -> int:
    """Index a closing case's IOCs without letting a failure fail the close.

    Runs in a SAVEPOINT: a failed statement rolls back to here and leaves the
    caller's transaction usable. Catching the error on a shared session without
    one would poison the transaction, so the caller's commit would raise anyway
    — which is the outcome this exists to avoid.
    """
    # Push the caller's own close out first, so the SAVEPOINT covers only our
    # inserts and rolling it back cannot undo the close. A failure here is the
    # close failing, and belongs to the caller.
    session.flush()
    try:
        with session.begin_nested():
            return SharedIOCRepository(session).record_case(case_id)
    except Exception as e:
        logger.error(
            "Failed to index shared IOCs for %s: %s", case_id, e, exc_info=True
        )
        return 0


class SharedIOCRepository:
    """Data access for the cross-investigation IOC index."""

    def __init__(self, session: Session):
        self.session = session

    # ---- writes --------------------------------------------------------

    def record(self, investigation_id: str, keys: Iterable[str]) -> int:
        """Index ``keys`` against an investigation, skipping ones already there.

        Returns the number of rows added. Re-indexing an investigation is a
        no-op, so callers may write the same indicators more than once.
        """
        pairs = {p for p in (split_key(k) for k in keys) if p is not None}
        if not pairs:
            return 0

        already = self.keys_for(investigation_id)
        added = 0
        for ioc_type, value in sorted(pairs):
            if f"{ioc_type}:{value}" in already:
                continue
            self.session.add(
                SharedIOC(
                    investigation_id=investigation_id,
                    ioc_type=ioc_type,
                    value=value,
                )
            )
            added += 1
        return added

    def record_case(self, case_id: str) -> int:
        """Index a case's IOCs against every investigation that belongs to it.

        ``shared_iocs.investigation_id`` is the table's only subject, so a case
        with no investigation contributes nothing — there is nothing to key the
        rows to. Attribution is at case granularity: an IOC an analyst added to
        the case is indexed against each of its investigations, not only the one
        that surfaced it.
        """
        keys = self._case_keys(case_id)
        if not keys:
            return 0

        investigation_ids = (
            self.session.execute(
                select(Investigation.investigation_id).where(
                    Investigation.case_id == case_id
                )
            )
            .scalars()
            .all()
        )
        return sum(self.record(inv_id, keys) for inv_id in investigation_ids)

    def record_case_for(self, case_id: str, investigation_id: str) -> int:
        """Index a case's IOCs against one named investigation of that case."""
        return self.record(investigation_id, self._case_keys(case_id))

    # ---- reads ---------------------------------------------------------

    def keys_for(self, investigation_id: str) -> Set[str]:
        """Every indicator key indexed for one investigation."""
        rows = self.session.execute(
            select(SharedIOC.ioc_type, SharedIOC.value).where(
                SharedIOC.investigation_id == investigation_id
            )
        ).all()
        return {f"{t}:{v}" for t, v in rows}

    def investigations_for(self, keys: Iterable[str]) -> Set[str]:
        """Every investigation that has seen any of ``keys``, open or finished.

        Empty when no investigation has seen any of them.
        """
        clauses = self._key_clauses(keys)
        if not clauses:
            return set()
        return set(
            self.session.execute(
                select(SharedIOC.investigation_id).where(or_(*clauses)).distinct()
            )
            .scalars()
            .all()
        )

    def open_investigations_for(self, keys: Iterable[str]) -> Set[str]:
        """As ``investigations_for``, restricted to investigations still open."""
        clauses = self._key_clauses(keys)
        if not clauses:
            return set()
        return set(
            self.session.execute(
                select(SharedIOC.investigation_id)
                .join(
                    Investigation,
                    Investigation.investigation_id == SharedIOC.investigation_id,
                )
                .where(or_(*clauses), Investigation.status.notin_(CLOSED_STATUSES))
                .distinct()
            )
            .scalars()
            .all()
        )

    def shared_between(self, inv_id_a: str, inv_id_b: str) -> Set[str]:
        """The indicator keys two investigations both have indexed."""
        return self.keys_for(inv_id_a) & self.keys_for(inv_id_b)

    # ---- internals -----------------------------------------------------

    def _case_keys(self, case_id: str) -> Set[str]:
        values = self.session.execute(
            select(CaseIOC.ioc_type, CaseIOC.value).where(CaseIOC.case_id == case_id)
        ).all()
        return {k for k in (make_key(t, v) for t, v in values) if k}

    @staticmethod
    def _key_clauses(keys: Iterable[str]) -> List[ColumnElement[bool]]:
        clauses: List[ColumnElement[bool]] = []
        for key in keys:
            pair = split_key(key)
            if pair is None:
                continue
            clauses.append(
                and_(SharedIOC.ioc_type == pair[0], SharedIOC.value == pair[1])
            )
        return clauses
