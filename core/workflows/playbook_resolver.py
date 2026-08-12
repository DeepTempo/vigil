# Resolves a Playbook reference into the two layers the agent layer parses. The
# reference is what the job carries; this is where it becomes a run's content.

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

import yaml

from core.llm.defaults import DEFAULT_MODEL

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


def _tool_catalogue() -> Dict[str, Dict[str, Any]]:
    from core.llm.tool_schemas import ALL_TOOLS

    return {tool["name"]: tool for tool in ALL_TOOLS if tool.get("name")}


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
def _tools_of(phases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    catalogue = _tool_catalogue()
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


def resolve(workflow_id: str, model: Optional[str] = None) -> Tuple[str, str]:
    """Return the playbook and config layers for ``workflow_id``, as YAML text."""
    from core.workflows.workflows_service import get_workflows_service

    definition = get_workflows_service().get_workflow(workflow_id)
    if definition is None:
        raise UnknownPlaybook(f"no such workflow: {workflow_id}")

    phases = _phases_of(definition)
    # Refused rather than run: a playbook with no steps completes instantly having
    # done nothing, which reads exactly like a run that worked.
    if not phases:
        raise UnknownPlaybook(f"{workflow_id} declares no phases; there is nothing to run")

    tools = _tools_of(phases)
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


# Block style and no aliases: the agent layer parses this, and a YAML anchor would
# arrive as a shared reference nobody on that side asked for.
def _dump(document: Dict[str, Any]) -> str:
    return yaml.safe_dump(
        document, default_flow_style=False, sort_keys=False, allow_unicode=True
    )
