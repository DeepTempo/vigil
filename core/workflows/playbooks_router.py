# How the TypeScript agent layer reads a Playbook. It answers with the two layer
# documents as text, so that side parses them with the readers it already has.

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from core.agents.internal_auth import authorise
from core.routing import Auth, RouterMeta
from core.workflows.playbook_resolver import UnknownPlaybook, resolve

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/internal/playbooks",
    tags=["internal-playbooks"],
    auth=Auth.ROUTER_MANAGED,
    reason=(
        "Loopback plus a shared secret: the caller is the agent layer, not a session."
    ),
)
logger = logging.getLogger(__name__)


class ResolvedPlaybook(BaseModel):
    playbook: str
    config: str


@router.get("/{workflow_id}", response_model=ResolvedPlaybook)
def get_playbook(
    workflow_id: str,
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> ResolvedPlaybook:
    authorise(request, authorization, "playbook resolution")

    try:
        playbook, config = resolve(workflow_id)
    except UnknownPlaybook as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None

    return ResolvedPlaybook(playbook=playbook, config=config)
