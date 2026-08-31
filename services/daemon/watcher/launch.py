"""Stage C of the Watcher: launch a hunt from a hypothesis set, and read it back.

Launch rides the console's own path — ``WorkflowsService.execute_workflow`` — so a
Watcher-launched hunt is indistinguishable from a human-launched one on the agent
layer: it enqueues onto the BullMQ ``agent-runs`` queue, the TS worker resolves the
``threat-hunt`` spec, merges in our hypotheses + context, and drives the hunt.

Reconcile is ``read_projection``: the run's own ledger (hypotheses + evidence for
and against each) read over HTTP from the agent layer. The daemon never writes
beside that ledger — it only reads a projection of it.

Both dependencies are injectable so this is testable without a live stack.
"""

from typing import Any, Dict, Optional

from services.daemon.watcher.schemas import WatcherHypothesisSet
from services.daemon.watcher.spec import HUNT_WORKFLOW_ID, build_hunt_parameters


async def launch_hunt(
    hypothesis_set: WatcherHypothesisSet,
    *,
    workflows: Any = None,
    triggered_by: str = "watcher",
    max_cost_usd: Optional[float] = None,
    iterations: Optional[int] = None,
) -> Dict[str, Any]:
    """Enqueue a threat hunt for one hypothesis set.

    Returns ``execute_workflow``'s result dict: on success
    ``{"success": True, "status": "queued", "run_id", "job_id", ...}``; on failure
    ``{"success": False, "error", ...}``. ``workflows`` (a ``WorkflowsService``) is
    injectable for tests; in the daemon it defaults to the real one.
    """
    if workflows is None:
        from core.workflows.workflows_service import WorkflowsService

        workflows = WorkflowsService()

    params = build_hunt_parameters(
        hypothesis_set, max_cost_usd=max_cost_usd, iterations=iterations
    )
    return await workflows.execute_workflow(
        HUNT_WORKFLOW_ID, params, triggered_by=triggered_by
    )


async def read_hunt(run_id: str, *, reader: Any = None) -> Optional[Dict[str, Any]]:
    """Read the hunt's projection (its ledger) for ``run_id``.

    ``None`` means nothing to read yet (the run hasn't been picked up, or the agent
    layer is unreachable) — not an error. ``reader`` is injectable for tests; in the
    daemon it defaults to ``read_projection``.
    """
    if reader is None:
        from core.agents.projections import read_projection

        reader = read_projection
    return await reader(run_id)
