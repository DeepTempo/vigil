# How the TypeScript agent layer reads a Playbook. It answers with the two layer
# documents as text, so that side parses them with the readers it already has.

from __future__ import annotations

import logging
from typing import Optional

from fastapi import Depends, APIRouter, Header, HTTPException
from pydantic import BaseModel

from core.agents.internal_auth import authorise
from core.deps import provide_mcp_registry, provide_workflows
from core.integrations.mcp.registry import MCPRegistry
from core.workflows.workflows_service import WorkflowsService
from core.routing import Auth, RouterMeta
from core.workflows.playbook_resolver import UnknownPlaybook, resolve, resolve_hunt

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/internal/playbooks",
    tags=["internal-playbooks"],
    auth=Auth.ROUTER_MANAGED,
    reason=(
        "A shared secret: the caller is the agent layer, not a session. Reachability\n"
        "is the NetworkPolicy's job since ADR 0014, not a loopback check."
    ),
)
logger = logging.getLogger(__name__)


class ResolvedPlaybook(BaseModel):
    playbook: str
    config: str


def _resolver_for(workflows: WorkflowsService, workflow_id: str):
    from core.workflows.workflows_service import HUNT_RUN_KIND

    definition = workflows.get_workflow(workflow_id)
    if definition is None:
        raise UnknownPlaybook(f"no such workflow: {workflow_id}")
    return resolve_hunt if definition.run_kind == HUNT_RUN_KIND else resolve


@router.get("/{workflow_id}", response_model=ResolvedPlaybook)
def get_playbook(
    workflow_id: str,
    authorization: Optional[str] = Header(default=None),
    workflows: WorkflowsService = Depends(provide_workflows),
    registry: MCPRegistry = Depends(provide_mcp_registry),
) -> ResolvedPlaybook:
    authorise(authorization, "playbook resolution")

    # The definition says which loop drives it, and the two loops read different
    # sections: a compose run wants phases, a hunt wants beliefs to test.
    try:
        playbook, config = _resolver_for(workflows, workflow_id)(workflow_id, workflows=workflows, registry=registry)
    except UnknownPlaybook as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None

    return ResolvedPlaybook(playbook=playbook, config=config)
