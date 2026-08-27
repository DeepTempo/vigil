"""Shared intelligence layer for cross-investigation correlation.

``shared_iocs`` is the index — nothing is held in process — so what two
investigations had in common last week is still known after a daemon restart.

Two questions are asked of it and they are not the same one. *Dedup* asks
whether a finding duplicates work already in flight, and is bounded to open
investigations: a finished investigation is not something a finding can be added
to, and letting history answer it would mean an indicator seen once is never
investigated again. *Correlation* asks what else has ever touched these
indicators, and reads the whole table.
"""

import logging
from contextlib import AbstractContextManager
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

from core.storage.connection import get_db_manager
from core.storage.shared_ioc_repository import SharedIOCRepository, make_key

logger = logging.getLogger(__name__)

# entity_context spellings, in the order a value is looked for. The list and
# scalar forms of the same entity both appear, depending on the source, and the
# alternatives within a tuple are aliases: the first one present wins.
_LIST_FIELDS = (
    ("ip", ("src_ips",)),
    ("ip", ("dest_ips", "dst_ips")),
    ("hostname", ("hostnames",)),
    ("user", ("usernames", "users")),
    ("hash", ("file_hashes",)),
    ("domain", ("domains",)),
)
_SCALAR_FIELDS = (
    ("ip", "src_ip"),
    ("ip", "dst_ip"),
    ("hostname", "hostname"),
    ("user", "user"),
)


def _keys_from_finding(finding: Dict[str, Any]) -> Set[str]:
    """Every indicator key a finding's entity context names."""
    ctx = finding.get("entity_context") or {}
    keys: Set[str] = set()

    for ioc_type, names in _LIST_FIELDS:
        values = next((ctx[n] for n in names if ctx.get(n)), None) or []
        for value in values:
            key = make_key(ioc_type, value)
            if key:
                keys.add(key)

    for ioc_type, name in _SCALAR_FIELDS:
        key = make_key(ioc_type, ctx.get(name))
        if key:
            keys.add(key)

    return keys


class SharedIntelligence:
    """Cross-investigation IOC tracker over ``shared_iocs``."""

    def __init__(
        self,
        session_scope: Optional[Callable[[], AbstractContextManager]] = None,
    ):
        self._session_scope = session_scope or (
            lambda: get_db_manager().session_scope()
        )

    def register_investigation(
        self, investigation_id: str, findings: Iterable[Dict[str, Any]]
    ):
        """Index the entities a new investigation's findings name.

        The investigation row must already exist — ``shared_iocs`` is keyed to
        it — so call this after the investigation is saved.
        """
        keys: Set[str] = set()
        for finding in findings:
            keys |= _keys_from_finding(finding)
        if not keys:
            return
        self._query("register", lambda repo: repo.record(investigation_id, keys), None)

    def check_overlap(
        self, finding: Dict[str, Any], exclude_id: Optional[str] = None
    ) -> List[str]:
        """Open investigations already covering one of this finding's entities."""
        keys = _keys_from_finding(finding)
        if not keys:
            return []

        overlapping = self._query(
            "overlap lookup", lambda repo: repo.open_investigations_for(keys), set()
        )
        if exclude_id:
            overlapping.discard(exclude_id)
        return sorted(overlapping)

    def get_related_investigations(self, investigation_id: str) -> List[str]:
        """Investigations that share an indicator with the given one, ever."""

        def _related(repo: SharedIOCRepository) -> Set[str]:
            keys = repo.keys_for(investigation_id)
            return repo.investigations_for(keys) if keys else set()

        related = self._query("related lookup", _related, set())
        related.discard(investigation_id)
        return sorted(related)

    def get_shared_iocs(self, inv_id_a: str, inv_id_b: str) -> List[str]:
        """Indicator keys shared between two investigations."""
        return sorted(
            self._query(
                "shared lookup",
                lambda repo: repo.shared_between(inv_id_a, inv_id_b),
                set(),
            )
        )

    def close_investigation(self, investigation_id: str, case_id: Optional[str]):
        """Index the closing investigation's case IOCs against it.

        Its own findings' entities went in when it was registered; this picks up
        what the case accumulated while it ran.
        """
        if not case_id:
            return
        self._query(
            "close write",
            lambda repo: repo.record_case_for(case_id, investigation_id),
            None,
        )

    def _query(self, operation: str, fn: Callable, default: Any) -> Any:
        try:
            with self._session_scope() as session:
                return fn(SharedIOCRepository(session))
        except Exception as e:
            logger.error("shared_iocs %s failed: %s", operation, e, exc_info=True)
            return default
