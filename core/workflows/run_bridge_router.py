# The projection of a run, written by the agent layer. Phase rows are what the UI
# reads; approval decisions travel back the other way for that layer to journal.

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header
from pydantic import BaseModel, Field

from core.agents.internal_auth import authorise
from core.deps import provide_approvals, provide_workflow_runs
from core.response.approval_service import ApprovalService
from core.response.checkpoints import raise_for_checkpoint, withdraw_for_run
from core.routing import Auth, RouterMeta
from core.time import utcnow
from core.workflows.workflow_run_service import WorkflowRunService

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/internal/runs",
    tags=["internal-runs"],
    auth=Auth.ROUTER_MANAGED,
    reason=(
        "A shared secret: the caller is the agent layer, not a session. Reachability\n"
        "is the NetworkPolicy's job since ADR 0014, not a loopback check."
    ),
)
logger = logging.getLogger(__name__)

WAITING = "pending_approval"

# What a run's status becomes when a phase reports one. A step that is waiting is
# the only one that says anything about the run as a whole.
RUN_STATUS = {WAITING: "paused", "running": "running", "completed": "running"}

# A run nobody stopped and nothing broke. Aborted and abandoned both read as
# crashes under "failed", and only one of the three is worth paging over.
# budget_exhausted is the same mistake one step along: a hunt that stopped at the
# ceiling its operator set did what it was told.
TERMINAL_STATUS = {
    "completed": "completed",
    "budget_exhausted": "completed",
    "aborted": "cancelled",
    "abandoned": "cancelled",
}


class PhaseUpdate(BaseModel):
    phase_id: str
    agent: str
    name: str
    order: int
    status: str
    approval_state: Optional[str] = None
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    checkpoint_id: Optional[str] = None
    question: Optional[str] = None


class TerminalHandoff(BaseModel):
    case_id: str
    title: str
    markdown: str = ""


class TerminalUpdate(BaseModel):
    outcome: str
    reason: str = ""
    summary: str = ""
    cost_usd: Optional[float] = None
    handoffs: List[TerminalHandoff] = Field(default_factory=list)


class CheckpointRaised(BaseModel):
    checkpoint_id: str
    checkpoint_class: str
    question: str
    raised_at: str = ""
    run_kind: str = ""
    context: Optional[Dict[str, Any]] = None


class Decision(BaseModel):
    checkpoint_id: str
    actor: str
    answer: str = Field(..., description="approve or reject")
    text: str = ""
    resolved_at: str


class Decisions(BaseModel):
    decisions: List[Decision] = []


@router.post("/{run_id}/phases", status_code=204)
def record_phase(
    run_id: str,
    update: PhaseUpdate,
    authorization: Optional[str] = Header(default=None),
    run_service: WorkflowRunService = Depends(provide_workflow_runs),
    approvals: ApprovalService = Depends(provide_approvals),
) -> None:
    authorise(authorization, "run progress")

    now = utcnow()
    run_service.upsert_phase(
        run_id,
        update.phase_id,
        phase_order=update.order,
        agent_id=update.agent,
        status=update.status,
        output=update.output,
        error=update.error,
        # The agent layer says how a gate was answered; a waiting step is the only
        # state this side can name on its own.
        approval_state=update.approval_state
        or ("pending" if update.status == WAITING else None),
        started_at=now if update.status == "running" else None,
        finished_at=now if update.status in ("completed", "failed") else None,
    )
    run_service.set_status(run_id, RUN_STATUS.get(update.status, "running"))

    if update.status == WAITING and update.checkpoint_id:
        _raise_approval(run_id, update, approvals)


@router.post("/{run_id}/terminal", status_code=204)
def record_terminal(
    run_id: str,
    update: TerminalUpdate,
    authorization: Optional[str] = Header(default=None),
    run_service: WorkflowRunService = Depends(provide_workflow_runs),
    approvals: ApprovalService = Depends(provide_approvals),
) -> None:
    authorise(authorization, "run outcome")

    withdraw_for_run(
        run_id,
        f"the run ended before this was answered: {update.reason or update.outcome}",
        approvals,
    )

    status = TERMINAL_STATUS.get(update.outcome, "failed")
    run_service.finalize_run(
        run_id,
        status=status,
        result_summary=update.summary or None,
        # Only a failure writes the error column, which the console renders under a
        # red heading. A run stopped at its ceiling has a reason, not an error, and
        # that reason is on the terminal event and in the report.
        error=update.reason if status == "failed" else None,
        cost_usd=update.cost_usd,
    )

    # The case the run was started from, so its report reaches the case rather than
    # living only in the run row.
    origin = _origin_case(run_id, run_service)
    if origin:
        _record_report(origin, run_id, update)

    # A threat hunt that proved a compromise tees up the backward root-cause run,
    # parked for the operator's go-ahead. Computed once: an RCA's own handoff
    # (run_kind root_cause) returns False, so a root cause never spawns another.
    # The forward hunt files each handoff the moment it lands (see the /handoff
    # route), so by the time its terminal arrives the case and RCA are usually
    # already teed up; _process_handoff is idempotent per handoff, so re-sending
    # them here is a safety net, not a second case.
    start_rca = _source_is_hunt(run_id, run_service)
    for handoff in update.handoffs:
        _process_handoff(run_id, handoff, origin, start_rca, run_service)


# A handoff pushed the moment the hunt journals it, ahead of the terminal that will
# carry it again. A forward hunt escalates and keeps hunting -- its terminal can be
# an hour of parking away, or never arrive -- so the case IR receives, and the
# root-cause run it tees up, are filed here rather than left waiting on that end.
@router.post("/{run_id}/handoff", status_code=204)
def record_handoff(
    run_id: str,
    handoff: TerminalHandoff,
    authorization: Optional[str] = Header(default=None),
    run_service: WorkflowRunService = Depends(provide_workflow_runs),
) -> None:
    authorise(authorization, "run handoff")
    origin = _origin_case(run_id, run_service)
    _process_handoff(
        run_id, handoff, origin, _source_is_hunt(run_id, run_service), run_service
    )


# Opens the case a handoff hands over and, for a hunt, tees up the backward run --
# once per handoff. Both the /handoff push and the terminal that re-carries it land
# here, so the RCA dedup guards the case too: a handoff whose root-cause run already
# exists has already opened its case, and a second call is a no-op rather than a
# duplicate.
def _process_handoff(
    run_id: str,
    handoff: TerminalHandoff,
    origin: str,
    start_rca: bool,
    run_service: WorkflowRunService,
) -> None:
    if start_rca and _rca_exists(run_id, handoff, run_service):
        return
    opened_case = _open_case(run_id, handoff, origin)
    if start_rca:
        _start_root_cause(run_id, handoff, opened_case)


def _origin_case(run_id: str, run_service: WorkflowRunService) -> str:
    run = run_service.get_run(run_id) or {}
    case_id = (run.get("trigger_context") or {}).get("case_id")
    return str(case_id) if case_id else ""


# Appended rather than written over: a case accumulates what was done to it, and the
# description is the analyst's own. activities is the list the case UI reads.
def _add_activity(
    case_id: str, activity_type: str, description: str, details: Dict[str, Any]
) -> None:
    from core.storage.database_data_service import DatabaseDataService

    data = DatabaseDataService()
    case = data.get_case(case_id)
    if not case:
        logger.warning("case %s is gone; %s not recorded on it", case_id, activity_type)
        return

    activities = list(case.get("activities") or [])
    activities.append(
        {
            "timestamp": utcnow().isoformat() + "Z",
            "activity_type": activity_type,
            "description": description,
            "details": details,
        }
    )
    data.update_case(case_id, activities=activities)


def _record_report(case_id: str, run_id: str, update: TerminalUpdate) -> None:
    try:
        _add_activity(
            case_id,
            "agent_run_report",
            update.summary or update.reason or update.outcome,
            {"run_id": run_id, "outcome": update.outcome, "cost_usd": update.cost_usd},
        )
    except Exception:  # noqa: BLE001 — the run ended either way
        logger.exception(
            "could not record the report of %s on case %s", run_id, case_id
        )


# A run that ended by handing work over opens the case that receives it. The agent
# layer holds no case table, so the document travels and this side files it.
def _open_case(
    run_id: str, handoff: TerminalHandoff, origin: str = ""
) -> Optional[str]:
    from core.storage.database_data_service import DatabaseDataService

    try:
        opened = DatabaseDataService().create_case(
            title=handoff.title[:200],
            finding_ids=[],
            priority="high",
            description=_with_origin(handoff.markdown, origin),
        )
    except Exception:  # noqa: BLE001 — the run ended either way
        logger.exception("could not open %s handed off by %s", handoff.case_id, run_id)
        return None

    opened_id = (opened or {}).get("case_id", "")
    # Both directions, so neither case is a dead end.
    if origin and opened_id:
        _record_handoff(origin, run_id, handoff, opened_id)
    return opened_id or None


def _source_is_hunt(run_id: str, run_service: WorkflowRunService) -> bool:
    """True only when ``run_id`` is a threat hunt (run_kind 'hunt') — the one kind
    whose handoff tees up a backward root-cause run. An RCA's own handoff resolves
    to run_kind 'root_cause' and returns False, so a root cause never spawns another.
    """
    from core.workflows.workflows_service import HUNT_RUN_KIND, WorkflowsService

    run = run_service.get_run(run_id) or {}
    wf_id = run.get("workflow_id")
    if not wf_id:
        return False
    try:
        workflow = WorkflowsService().get_workflow(str(wf_id))
    except Exception:  # noqa: BLE001 — a missing workflow just means no RCA
        return False
    return bool(workflow and workflow.run_kind == HUNT_RUN_KIND)


# The join key tying a backward root-cause run to the handoff it traces back from.
# One spelling, since both the dedup check and the enqueue key off it.
def _triggered_by(source_run_id: str, handoff: TerminalHandoff) -> str:
    return f"handoff:{source_run_id}:{handoff.case_id}"


# Whether the backward run for this handoff was already teed up, keyed by the
# handoff it traces back from. Guards both the case and the RCA, since a handoff
# arrives twice -- once pushed the moment it lands, once on the terminal that
# re-carries it -- and the second must open nothing new. Fail-open: a missed dedup
# is a duplicate case, better than no root-cause run at all.
def _rca_exists(
    source_run_id: str, handoff: TerminalHandoff, run_service: WorkflowRunService
) -> bool:
    triggered_by = _triggered_by(source_run_id, handoff)
    try:
        existing = run_service.list_runs(workflow_id="root-cause-analysis", limit=50)
        return any(r.get("triggered_by") == triggered_by for r in existing)
    except Exception:  # noqa: BLE001 — a missed dedup is better than no RCA
        logger.exception("could not check for an existing root-cause run")
        return False


# A proven hunt hands off; the RCA that traces how it started is teed up here rather
# than left for someone to remember. It parks at its hypothesis_approval checkpoint
# (root-cause-analysis declares it "ask"), so it waits in the same approvals inbox a
# hunt uses for the operator to go ahead. The backward hypothesis is derived from the
# handoff finding, which already carries the confirmed claim — not the later report.
# _process_handoff has already guarded on _rca_exists, so this is the sole tee-up.
def _start_root_cause(
    source_run_id: str,
    handoff: TerminalHandoff,
    opened_case: Optional[str],
) -> None:
    params = {
        "hypothesis": _rca_hypothesis(handoff),
        "context": _rca_context(handoff),
        "agent_id": "threat_hunter",
        # Files the RCA's report back onto the IR case the hunt opened, and lets it
        # read that case's finding as target context.
        "case_id": opened_case or handoff.case_id,
        "source_run_id": source_run_id,
    }
    try:
        asyncio.run(_enqueue_root_cause(params, _triggered_by(source_run_id, handoff)))
    except Exception:  # noqa: BLE001 — the case it opened is the deliverable
        logger.exception(
            "could not tee up a root-cause run for handoff %s of %s",
            handoff.case_id,
            source_run_id,
        )


async def _enqueue_root_cause(params: Dict[str, Any], triggered_by: str) -> None:
    from core.workflows.workflows_service import WorkflowsService

    await WorkflowsService().execute_workflow(
        "root-cause-analysis", params, triggered_by=triggered_by
    )


# A Windows hostname (FYODOR-L) if the handoff names one, else the first IP. The
# hypothesis reads better naming the host, but a run still starts without one.
_HOST_RE = re.compile(r"\b[A-Z][A-Z0-9]+-[A-Z0-9]+\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _rca_subject(handoff: TerminalHandoff) -> str:
    text = f"{handoff.title}\n{handoff.markdown}"
    host = _HOST_RE.search(text)
    if host:
        return host.group(0)
    ip = _IP_RE.search(text)
    return ip.group(0) if ip else "the confirmed-compromised host"


def _rca_hypothesis(handoff: TerminalHandoff) -> str:
    return (
        f"{_rca_subject(handoff)} was compromised via an initial-access vector that "
        f"led to the confirmed threat escalated as {handoff.case_id}; establish how "
        "the attacker first got onto this host — the initial-access vector and "
        "patient zero."
    )


def _rca_context(handoff: TerminalHandoff) -> str:
    finding = handoff.markdown.strip() or handoff.title
    return (
        "This run follows a CONFIRMED compromise handed to incident response. The "
        "confirmed finding to work backward from:\n\n"
        f"{finding}\n\n"
        "Work BACKWARD to the initial-access vector: find the earliest malicious "
        "activity that PRECEDES the confirmed compromise, what was delivered to the "
        "user and how, and when. Report the initial-access vector confirmed / "
        "refuted / inconclusive with the specific artifact, delivery method, and "
        "timestamp."
    )


def _with_origin(markdown: str, origin: str) -> str:
    return f"{markdown}\n\n_Escalated from case {origin}._\n" if origin else markdown


def _record_handoff(
    case_id: str, run_id: str, handoff: TerminalHandoff, opened: str
) -> None:
    try:
        _add_activity(
            case_id,
            "agent_run_handoff",
            f"Escalated to incident response as "
            f"{opened or handoff.case_id}: {handoff.title}",
            {"run_id": run_id, "case_id": opened, "handoff_id": handoff.case_id},
        )
    except Exception:  # noqa: BLE001 — the case it opened is the deliverable
        logger.exception("could not link %s back to case %s", opened, case_id)


# A run parked on a checkpoint, as a question in the approvals inbox. Only the
# compose path raised these before, so a hunt parked where nobody could see it.
@router.post("/{run_id}/checkpoints", status_code=204)
def record_checkpoint(
    run_id: str,
    raised: CheckpointRaised,
    authorization: Optional[str] = Header(default=None),
    approvals: ApprovalService = Depends(provide_approvals),
) -> None:
    authorise(authorization, "run checkpoint")

    # Idempotent per checkpoint inside raise_for_checkpoint, because a parked run
    # is announced on every sweep and would otherwise queue the question each time.
    raise_for_checkpoint(
        run_id=run_id,
        checkpoint_id=raised.checkpoint_id,
        title=raised.question[:120] or raised.checkpoint_class,
        description=raised.question,
        reason=f"The run parked on a {raised.checkpoint_class} checkpoint",
        parameters={
            "checkpoint_class": raised.checkpoint_class,
            "run_kind": raised.run_kind,
            **(raised.context or {}),
        },
        approvals=approvals,
    )


# The approvals table is the inbox. An analyst answers there, the agent layer
# reads the answer here, and that layer alone writes it onto the ledger.
@router.get("/{run_id}/decisions", response_model=Decisions)
def list_decisions(
    run_id: str,
    authorization: Optional[str] = Header(default=None),
    approvals: ApprovalService = Depends(provide_approvals),
) -> Decisions:
    from core.response.approval_service import ActionStatus

    authorise(authorization, "run decisions")

    decided: List[Decision] = []
    for status, answer in (
        (ActionStatus.APPROVED, "approve"),
        (ActionStatus.REJECTED, "reject"),
    ):
        for action in approvals.list_actions(status=status, workflow_run_id=run_id):
            checkpoint = (action.parameters or {}).get("checkpoint_id")
            if not checkpoint:
                continue
            decided.append(
                Decision(
                    checkpoint_id=str(checkpoint),
                    actor=action.approved_by or "analyst",
                    answer=answer,
                    text=action.rejection_reason or "",
                    resolved_at=action.approved_at or utcnow().isoformat(),
                )
            )
    return Decisions(decisions=decided)


# Named by the checkpoint the agent layer raised, so the decision travels back
# addressed to the step that is waiting and to no other.
def _raise_approval(
    run_id: str, update: PhaseUpdate, approvals: ApprovalService
) -> None:
    raise_for_checkpoint(
        run_id=run_id,
        checkpoint_id=str(update.checkpoint_id),
        title=update.question or f"Approve {update.name}",
        description=update.question or f"Phase {update.order}: {update.name}",
        reason="The playbook marks this phase approval_required",
        parameters={"phase_id": update.phase_id, "agent_id": update.agent},
        phase_id=update.phase_id,
        approvals=approvals,
    )
