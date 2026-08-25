"""Agents API endpoints for SOC agent management."""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.agents.builtins import DEFAULT_AGENT_ID
from core.agents.manager import CUSTOM_AGENT_ID_PREFIX, AgentManager
from core.routing import Auth, RouterMeta

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/agents",
    tags=["agents"],
    auth=Auth.REQUIRED,
)
logger = logging.getLogger(__name__)

# Global agent manager instance
agent_manager = AgentManager()


def _resolve_agent(agent_id: str):
    """Resolve an agent_id to an AgentProfile, lazy-loading custom agents on miss.

    Built-in agents are served from the in-memory dict with zero DB calls.
    Only misses for IDs prefixed with custom- trigger a refresh and retry.
    """
    agent = agent_manager.agents.get(agent_id)
    if agent is not None:
        return agent
    if agent_id and agent_id.startswith(CUSTOM_AGENT_ID_PREFIX):
        agent_manager.refresh_custom_agents()
        return agent_manager.agents.get(agent_id)
    return None


class InvestigationRequest(BaseModel):
    """Request to start an investigation with an agent."""

    finding_id: str
    agent_id: Optional[str] = DEFAULT_AGENT_ID
    additional_context: Optional[str] = None


@router.get("/agents")
async def list_agents():
    """Get list of all available SOC agents (built-ins + DB-backed customs).

    Always refreshes the custom-agent side of the cache from the DB so
    callers see rows created by other worker processes or external
    tooling without having to restart. Built-ins are code-defined and
    cached in-process.
    """
    # Cheap best-effort refresh. Failures leave the existing cache in
    # place — you'd still get the built-in list back.
    agent_manager.refresh_custom_agents()
    agents = agent_manager.get_agent_list()
    return {"agents": agents, "current_agent": agent_manager.current_agent_id}


@router.get("/agents/{agent_id}")
async def get_agent(agent_id: str):
    """
    Get details for a specific agent.

    Args:
        agent_id: The agent ID

    Returns:
        Agent details
    """
    agent = _resolve_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent not found: {agent_id}")

    return {
        "id": agent.id,
        "name": agent.name,
        "description": agent.description,
        "icon": agent.icon,
        "color": agent.color,
        "specialization": agent.specialization,
        "recommended_tools": agent.recommended_tools,
        "max_tokens": agent.max_tokens,
        "enable_thinking": agent.enable_thinking,
    }


@router.post("/agents/set-current")
async def set_current_agent(agent_id: str):
    """
    Set the current active agent.

    Args:
        agent_id: The agent ID to set as current

    Returns:
        Success status
    """
    success = agent_manager.set_current_agent(agent_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Agent not found: {agent_id}")

    return {"success": True, "current_agent": agent_manager.current_agent_id}


@router.post("/agents/investigate")
async def start_investigation(request: InvestigationRequest):
    """
    Start an investigation on a finding with a specific agent.

    Args:
        request: Investigation request with finding ID and agent

    Returns:
        Investigation prompt and agent details
    """
    from core.storage.database_data_service import DatabaseDataService

    try:
        # Get the finding
        data_service = DatabaseDataService()
        finding = data_service.get_finding(request.finding_id)

        if not finding:
            raise HTTPException(
                status_code=404, detail=f"Finding not found: {request.finding_id}"
            )

        # Get the agent
        agent = _resolve_agent(request.agent_id)
        if not agent:
            raise HTTPException(
                status_code=404, detail=f"Agent not found: {request.agent_id}"
            )

        # Construct investigation prompt
        techniques = finding.get("predicted_techniques", [])
        technique_str = (
            ", ".join([t.get("technique_id", "") for t in techniques])
            if techniques
            else "None"
        )

        prompt = f"""Please investigate this security finding:

**Finding ID:** {finding.get('finding_id')}
**Severity:** {finding.get('severity')}
**Data Source:** {finding.get('data_source')}
**Timestamp:** {finding.get('timestamp')}
**Anomaly Score:** {finding.get('anomaly_score', 'N/A')}
**Description:** {finding.get('description', 'N/A')}
**Predicted MITRE ATT&CK Techniques:** {technique_str}

{f'**Additional Context:** {request.additional_context}' if request.additional_context else ''}

Please conduct a thorough investigation of this finding. Use your available tools to gather more information, correlate with other findings, and provide your analysis."""

        return {
            "prompt": prompt,
            "agent": {
                "id": agent.id,
                "name": agent.name,
                "icon": agent.icon,
                "color": agent.color,
                "system_prompt": agent.system_prompt,
            },
            "finding": finding,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting investigation: {e}")
        raise HTTPException(status_code=500, detail=str(e))
