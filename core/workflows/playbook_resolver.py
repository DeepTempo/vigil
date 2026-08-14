# Resolves a Playbook reference into the two layers the agent layer parses. The
# reference is what the job carries; this is where it becomes a run's content.

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

import yaml

from core.llm.defaults import DEFAULT_MODEL

if TYPE_CHECKING:
    from core.integrations.mcp.registry import MCPRegistry
    from core.workflows.workflows_service import WorkflowsService

logger = logging.getLogger(__name__)


class UnknownPlaybook(Exception):
    pass


# Named for what the agent layer already defaults to, so a resolved config that
# states nothing unusual states the same numbers a packaged one would.
DEFAULT_SPEND = {"max_cost_usd": 5.0, "max_wall_ms": 1_800_000}
DEFAULT_RUNTIME = {"max_turns": 8, "result_cap": 20_000, "recall_limit": 3}

# Two attempts at the answer follow a phase's tool loop, so a phase costs at most
# this many model calls.
EMIT_ATTEMPTS = 2

REMOTE = "remote"


def _tool_catalogue(registry: Optional["MCPRegistry"]) -> Dict[str, Dict[str, Any]]:
    from core.llm.tool_schemas import ALL_TOOLS

    catalogue = {tool["name"]: tool for tool in ALL_TOOLS if tool.get("name")}
    # The integrations this deployment carries, as tools with the same shape. A
    # server that is not connected reports nothing, so it binds nothing.
    for tool in _mcp_catalogue(registry):
        catalogue.setdefault(tool["name"], tool)
    return catalogue


def _mcp_catalogue(registry: Optional["MCPRegistry"]) -> List[Dict[str, Any]]:
    if registry is None:
        return []
    try:
        return registry.get_all_tools()
    except Exception as exc:  # noqa: BLE001
        logger.debug("MCP registry unavailable while resolving tools: %s", exc)
        return []


# What an arch means when it asks for a capability, in the order a deployment
# should prefer. First one present wins; none present drops the capability.
CAPABILITIES: Dict[str, Tuple[str, ...]] = {
    "telemetry_search": (
        "splunk_search",
        "elastic_search",
        "azure-sentinel_query",
        "gcp-secops_search",
        "crowdstrike_query",
    ),
    "indicator_lookup": (
        "lookup_indicators",
        "virustotal_lookup",
        "alienvault-otx_indicator",
        "misp_search",
    ),
    "findings_search": ("search_findings",),
    "similar_findings": ("nearest_neighbors",),
}


# The tools that answer each capability the arch asked for, bound to what this
# deployment reports. provides is what the agent layer matches a role's needs on.
def _bound_capabilities(
    needs: List[str], catalogue: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    bound: List[Dict[str, Any]] = []
    for capability in needs:
        for candidate in CAPABILITIES.get(capability, ()):
            entry = catalogue.get(candidate)
            if entry is None:
                continue
            bound.append(
                {
                    "id": candidate,
                    "kind": REMOTE,
                    "provides": capability,
                    "description": entry.get("description", ""),
                    "parameters": entry.get("input_schema") or {},
                }
            )
            break
        else:
            logger.warning(
                "no tool in this deployment provides %s; roles needing it lose it",
                capability,
            )
    return bound


# An agent's prompt is rendered now rather than read from a file: the memory-palace
# block depends on what is connected, so a stored copy would describe another run.
def _prompt_for(agent_id: str) -> str:
    from core.agents.manager import SOCAgentLibrary

    profile = SOCAgentLibrary.get_agent(agent_id)
    if profile is None:
        raise UnknownPlaybook(f"phase names agent {agent_id}, which does not exist")
    return profile.system_prompt


# A file playbook writes one instructions block. A custom workflow authors the same
# thing as purpose, numbered steps and an expected output, and all three are it.
def _instructions_of(phase: Dict[str, Any]) -> str:
    stated = (phase.get("instructions") or "").strip()
    if stated:
        return stated

    parts = [(phase.get("purpose") or "").strip()]
    steps = [str(s).strip() for s in (phase.get("steps") or []) if str(s).strip()]
    if steps:
        parts.append("\n".join(f"{i}. {s}" for i, s in enumerate(steps, start=1)))
    expected = (phase.get("expected_output") or "").strip()
    if expected:
        parts.append(f"Expected output: {expected}")

    return "\n\n".join(part for part in parts if part)


def _phases_of(definition: Any) -> List[Dict[str, Any]]:
    resolved: List[Dict[str, Any]] = []
    for index, phase in enumerate(definition.phases):
        phase = phase or {}
        agent = phase.get("agent") or phase.get("agent_id") or ""
        if not agent:
            raise UnknownPlaybook(f"phase {index + 1} names no agent")

        resolved.append(
            {
                "id": phase.get("id") or phase.get("phase_id") or f"phase-{index + 1}",
                "agent": agent,
                "name": phase.get("name") or f"Phase {index + 1}",
                "instructions": _instructions_of(phase),
                "approval_required": bool(phase.get("approval_required")),
                "tools": list(phase.get("tools") or []),
                "prompt": _prompt_for(agent),
            }
        )
    return resolved


# Only what some step may actually call. A catalogue handed to the registry would
# widen every grant to everything, which is the opposite of deny-by-default.
def _tools_of(
    phases: List[Dict[str, Any]], registry: Optional["MCPRegistry"]
) -> List[Dict[str, Any]]:
    catalogue = _tool_catalogue(registry)
    wanted: List[str] = []
    for phase in phases:
        for tool in phase["tools"]:
            if tool not in wanted:
                wanted.append(tool)

    tools: List[Dict[str, Any]] = []
    for name in wanted:
        entry = catalogue.get(name)
        if entry is None:
            # Dropped rather than fatal: a playbook naming a tool this deployment
            # does not carry should lose that tool, not fail to run at all.
            logger.warning("playbook names unknown tool %s; dropping it", name)
            continue
        tools.append(
            {
                "id": name,
                "kind": REMOTE,
                "description": entry.get("description", ""),
                "parameters": entry.get("input_schema") or {},
            }
        )
    return tools


# Derived, not a constant: max_turns bounds a phase and this bounds the run, so a
# flat ceiling would starve a long playbook part-way through. Cost and wall bind.
def _budgets(phases: List[Dict[str, Any]]) -> Dict[str, Any]:
    per_phase = int(DEFAULT_RUNTIME["max_turns"]) + EMIT_ATTEMPTS
    return {"max_calls": max(len(phases), 1) * per_phase, **DEFAULT_SPEND}


def _drop_missing(phases: List[Dict[str, Any]], declared: List[str]) -> None:
    for phase in phases:
        phase["tools"] = [tool for tool in phase["tools"] if tool in declared]


def resolve(
    workflow_id: str,
    model: Optional[str] = None,
    workflows: Optional["WorkflowsService"] = None,
    registry: Optional["MCPRegistry"] = None,
) -> Tuple[str, str]:
    """Return the playbook and config layers for ``workflow_id``, as YAML text."""
    from core.integrations.mcp.registry import MCPRegistry
    from core.workflows.workflows_service import WorkflowsService

    definition = (workflows or WorkflowsService()).get_workflow(workflow_id)
    if definition is None:
        raise UnknownPlaybook(f"no such workflow: {workflow_id}")

    phases = _phases_of(definition)
    # Refused rather than run: a playbook with no steps completes instantly having
    # done nothing, which reads exactly like a run that worked.
    if not phases:
        raise UnknownPlaybook(f"{workflow_id} declares no phases; there is nothing to run")

    tools = _tools_of(phases, registry)
    _drop_missing(phases, [tool["id"] for tool in tools])

    playbook = {
        "name": definition.name,
        "description": definition.description,
        "use_case": definition.use_case,
        "trigger_examples": list(definition.trigger_examples),
        "objectives": list(definition.metadata.get("objectives") or []),
        "scope": dict(definition.metadata.get("scope") or {}),
        "directives": dict(definition.metadata.get("directives") or {}),
        "phases": phases,
        "narrative": definition.body,
    }

    config = {
        "model": model or DEFAULT_MODEL,
        "budgets": _budgets(phases),
        "runtime": DEFAULT_RUNTIME,
        "tools": tools,
        # Empty by design: a phase stops for a human through its own checkpoint,
        # which is a property of the step rather than of a tool it happens to call.
        "approvals": [],
        "thresholds": {},
    }

    return _dump(playbook), _dump(config)


# What the threathunt arch asks for, by capability. Duplicated across the language
# boundary for the same reason RUN_KINDS is, and held to it by a ratchet.
HUNT_CAPABILITIES = ("findings_search", "similar_findings", "telemetry_search", "indicator_lookup")

# A hunt is bounded by iterations rather than phases, and each one costs a lead
# turn, its workers and the critic. Wider than a compose run of the same size.
HUNT_BUDGETS = {"max_calls": 24, "max_cost_usd": 10.0, "max_wall_ms": 1_800_000}

# The null hypothesis on the board from the start. Without it the benign
# explanation is only ever an objection, never a competing claim -- which is the
# whole protection against a loop that searches until it finds something.
HUNT_HYPOTHESIS_LOOP = True


def _strings(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value or [] if str(item).strip()]


# The two layers a hunt run needs. Same tools and the same dump as a compose one;
# what differs is that a hunt states beliefs to test where a compose states steps.
def resolve_hunt(
    workflow_id: str,
    model: Optional[str] = None,
    workflows: Optional["WorkflowsService"] = None,
    registry: Optional["MCPRegistry"] = None,
) -> Tuple[str, str]:
    from core.integrations.mcp.registry import MCPRegistry
    from core.workflows.workflows_service import WorkflowsService

    definition = (workflows or WorkflowsService()).get_workflow(workflow_id)
    if definition is None:
        raise UnknownPlaybook(f"no such workflow: {workflow_id}")

    hypotheses = _strings(definition.metadata.get("hypotheses"))
    # Refused rather than run: a hunt with nothing to test would open a ledger,
    # spend a lead turn and conclude having tested nothing.
    if not hypotheses:
        raise UnknownPlaybook(f"{workflow_id} declares no hypotheses; there is nothing to test")

    playbook = {
        "name": definition.name,
        "description": definition.description,
        "use_case": definition.use_case,
        "trigger_examples": list(definition.trigger_examples),
        "objectives": _strings(definition.metadata.get("objectives")),
        "scope": dict(definition.metadata.get("scope") or {}),
        "directives": dict(definition.metadata.get("directives") or {}),
        "hypotheses": hypotheses,
        "attack_techniques": _strings(definition.metadata.get("attack_techniques")),
        "data_domains": _strings(definition.metadata.get("data_domains")),
        "narrative": definition.body,
    }

    config = {
        "model": model or DEFAULT_MODEL,
        "budgets": dict(HUNT_BUDGETS),
        "runtime": DEFAULT_RUNTIME,
        "tools": _bound_capabilities(list(HUNT_CAPABILITIES), _tool_catalogue(registry)) + [_expand_tool()],
        # The hunt gates on its own checkpoint classes, which are a property of
        # what it is about to conclude rather than of a tool it happens to call.
        "approvals": [],
        "thresholds": {},
        "hypothesis_loop": HUNT_HYPOTHESIS_LOOP,
    }

    return _dump(playbook), _dump(config)


# Local, because the answer is the run's own ledger. Declared here so the lead's
# granted expand resolves to something rather than posting to a backend.
def _expand_tool() -> Dict[str, Any]:
    return {
        "id": "expand",
        "kind": "local",
        "description": "Return the raw payloads behind evidence ids from this run's own record.",
        "parameters": {
            "type": "object",
            "required": ["evidence_ids"],
            "properties": {"evidence_ids": {"type": "array", "items": {"type": "string"}}},
        },
    }


# Block style and no aliases: the agent layer parses this, and a YAML anchor would
# arrive as a shared reference nobody on that side asked for.
def _dump(document: Dict[str, Any]) -> str:
    return yaml.safe_dump(
        document, default_flow_style=False, sort_keys=False, allow_unicode=True
    )
