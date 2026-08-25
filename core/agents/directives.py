# Queue an operator's directive for a running agent. It lands in agent_directives,
# never agent_events: enqueuing is open to any process, journaling is not.

from __future__ import annotations

import json
import logging
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# The vocabulary TypeScript's DIRECTIVE_KINDS declares, duplicated across the
# language boundary so a typo is a 4xx rather than a directive the drain refuses.
DIRECTIVE_KINDS = (
    "note",
    "lead",
    "abort",
    "extend",
    "conclude",
    "approve",
    "reject",
    "benign",
    "gap",
    "boost",
)

# What a directive may carry beyond its text. Anything outside this set is the
# caller's mistake rather than something to persist and puzzle over later.
DIRECTIVE_FIELDS = (
    "checkpoint_id",
    "entity_key",
    "question_id",
    "hypothesis_id",
    "tenant",
    "revoke",
)


# Malformed, so it is refused before it reaches the queue.
class InvalidDirective(ValueError):
    pass


# No ledger under that run id, so nothing would ever drain the directive.
class UnknownRun(InvalidDirective):
    pass


# The run journaled its terminal, so no drain will run again.
class RunAlreadyEnded(InvalidDirective):
    pass


def new_directive_id() -> str:
    return f"dir-{secrets.token_hex(4)}"


def build_directive(
    kind: str,
    body: str,
    actor: str,
    fields: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if kind not in DIRECTIVE_KINDS:
        raise InvalidDirective(f"unknown directive kind {kind}")
    if not actor:
        # Attribution is the point of the record: a directive nobody owns makes
        # the ledger unable to say who steered the run.
        raise InvalidDirective("a directive needs an actor")

    extra = fields or {}
    unknown = sorted(set(extra) - set(DIRECTIVE_FIELDS))
    if unknown:
        raise InvalidDirective(f"unknown directive fields: {', '.join(unknown)}")

    return {
        "directive_id": new_directive_id(),
        "actor": actor,
        "kind": kind,
        "text": body,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "origin": "inbox",
        **{name: value for name, value in extra.items() if value is not None},
    }


# The reads agent_runs_router already makes, in one pass: a directive is only
# worth queueing while the run has a ledger and has not journaled its terminal.
def _refuse_unless_running(session: Session, run_id: str) -> None:
    row = session.execute(
        text(
            "SELECT count(*) AS events, "
            "count(*) FILTER (WHERE kind = 'terminal') AS ended "
            "FROM agent_events WHERE run_id = CAST(:run_id AS uuid)"
        ),
        {"run_id": run_id},
    ).one()
    if int(row.events) == 0:
        raise UnknownRun(f"no such run: {run_id}")
    if int(row.ended) > 0:
        raise RunAlreadyEnded(f"run {run_id} has already ended")


# A parked run's due date pulled forward, so the watchdog takes it on the next sweep.
# Only a run nobody holds: moving a live worker's deadline would declare it dead.
def _wake(session: Session, run_id: str) -> None:
    session.execute(
        text(
            "UPDATE agent_run_leases SET claim_until = now() "
            "WHERE run_id = CAST(:run_id AS uuid) AND owner IS NULL"
        ),
        {"run_id": run_id},
    )


# Idempotent on directive_id, so a retried request is not a second directive. The
# columns are the shared envelope; the payload carries what only a workflow reads.
def enqueue_directive(
    session: Session,
    run_id: str,
    kind: str,
    body: str,
    actor: str,
    fields: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    try:
        uuid.UUID(run_id)
    except ValueError:
        raise InvalidDirective(f"not a run id: {run_id}") from None

    # A well-formed id for a run that never existed or has already ended would
    # queue a row nothing drains, and the operator would be told it took effect.
    _refuse_unless_running(session, run_id)

    directive = build_directive(kind, body, actor, fields)
    _wake(session, run_id)
    session.execute(
        text(
            "INSERT INTO agent_directives "
            "(run_id, directive_id, kind, actor, created_at, payload) "
            "VALUES (CAST(:run_id AS uuid), :directive_id, :kind, :actor, "
            "CAST(:created_at AS timestamptz), CAST(:payload AS jsonb)) "
            "ON CONFLICT (directive_id) DO NOTHING"
        ),
        {
            "run_id": run_id,
            "directive_id": directive["directive_id"],
            "kind": directive["kind"],
            "actor": directive["actor"],
            "created_at": directive["created_at"],
            "payload": json.dumps(directive),
        },
    )
    logger.info(
        "queued %s directive %s for run %s", kind, directive["directive_id"], run_id
    )
    return directive
