"""Stage B of the Watcher: turn a hypothesis set into hunt-launch parameters.

The hunt engine only has a per-run door for ONE of the four things the
Hypothesizer produces: ``hypotheses``. ``attack_techniques``, ``data_domains``,
and ``scope`` have no per-run channel — the agent contract sources them only from
a stored hunt definition's front-matter (see the resolution path in
``services/agent/worker.ts`` / ``core/workflows/playbook_resolver.py``). Rather
than fight that (a synthesized definition file or a contract change), we fold
those three into the **target-context prompt** the hunt already receives. The
hunt's Lead reads that context, so it still gets "focus on T1071.004, look in
dns/network, these are the entities" — as natural language instead of as
schema-narrowing fields. We lose only the worker-output-schema enum narrowing,
never the information.

So Stage B is a pure mapping ``WatcherHypothesisSet -> parameters`` for
``WorkflowsService.execute_workflow(HUNT_WORKFLOW_ID, parameters)`` — the exact
call the console makes, just driven by the machine. Enqueueing is Stage C.
"""

from typing import Any, Dict, List, Optional

from services.daemon.watcher.schemas import WatcherHypothesisSet

# The shipped hunt definition the console references; resolves run_kind: hunt and
# binds telemetry_search to whatever live MCP server the deployment carries.
HUNT_WORKFLOW_ID = "threat-hunt"


def _render_scope(scope: Dict[str, List[str]]) -> List[str]:
    lines: List[str] = []
    for bucket, values in scope.items():
        if values:
            lines.append(f"- {bucket}: {', '.join(values)}")
    return lines


def _render_context(hypothesis_set: WatcherHypothesisSet) -> str:
    """The Hypothesizer's judgement, as context the hunt Lead reads. Carries the
    three fields the per-run contract can't take (techniques, domains, scope)."""
    techniques = ", ".join(hypothesis_set.attack_techniques) or "none inferred"
    domains = ", ".join(hypothesis_set.data_domains) or "unspecified"
    scope_lines = _render_scope(hypothesis_set.scope) or ["- (no entities extracted)"]

    parts = [
        "**Watcher hypothesis context** "
        "(formed from the triggering alert, to be tested — not a conclusion)",
        hypothesis_set.narrative,
        f"Suspected MITRE techniques: {techniques}",
        f"Data domains to search: {domains}",
        "Entities in scope:",
        *scope_lines,
    ]
    return "\n".join(parts)


def build_hunt_parameters(
    hypothesis_set: WatcherHypothesisSet,
    *,
    max_cost_usd: Optional[float] = None,
    iterations: Optional[int] = None,
) -> Dict[str, Any]:
    """Map a hypothesis set to the parameters for ``execute_workflow``.

    - ``hypothesis``: the testable claims, one per line — the hunt seeds these as
      operator hypotheses (peers of the definition's, if any).
    - ``finding_id``: the source alert, so the target-context builder pulls the
      canonical finding block from the store.
    - ``context``: the Hypothesizer's narrative + techniques + domains + scope,
      folded in because the per-run contract can't carry the last three.

    ``max_cost_usd`` / ``iterations`` are optional per-run budget/depth knobs; when
    unset the hunt keeps the definition's shipped policy.
    """
    params: Dict[str, Any] = {
        "hypothesis": "\n".join(hypothesis_set.hypotheses),
        "finding_id": hypothesis_set.source_finding_id,
        "context": _render_context(hypothesis_set),
    }
    if max_cost_usd is not None:
        params["max_cost_usd"] = max_cost_usd
    if iterations is not None:
        params["iterations"] = iterations
    return params
