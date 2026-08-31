"""Unit tests for recall_entity tool grant and read-only memory prompts (GH #735)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO))

from core.agents.builtins import BUILTIN_AGENTS, AgentId
from core.agents.prompts import (
    _MEMORY_BLOCK,
    _memory_section,
    render_base_prompt,
)

pytestmark = pytest.mark.unit


def test_recall_entity_in_every_builtin_recommended_tools():
    """Every built-in agent must carry recall_entity in recommended_tools (#735)."""
    assert len(BUILTIN_AGENTS) == 13
    for agent in BUILTIN_AGENTS:
        tools = agent.get("recommended_tools", [])
        assert (
            "recall_entity" in tools
        ), f"Agent {agent['id']} is missing recall_entity in recommended_tools"


def test_no_mempalace_write_tools_in_recommended_tools():
    """No agent may declare mempalace write tools (#735)."""
    forbidden_tools = {
        "mempalace_add_drawer",
        "mempalace_delete_drawer",
        "mempalace_kg_add",
        "mempalace_kg_invalidate",
        "mempalace_diary_write",
    }
    for agent in BUILTIN_AGENTS:
        tools = set(agent.get("recommended_tools", []))
        overlap = tools & forbidden_tools
        assert not overlap, f"Agent {agent['id']} carries write tools: {overlap}"


def test_memory_block_is_read_only():
    """Memory operations block must mention recall_entity and instruct not to write."""
    assert "recall_entity" in _MEMORY_BLOCK
    assert "do not write to memory" in _MEMORY_BLOCK
    assert "mempalace_add_drawer" not in _MEMORY_BLOCK
    assert "mempalace_diary_write" not in _MEMORY_BLOCK
    assert "BEFORE starting" not in _MEMORY_BLOCK
    assert "DURING investigation" not in _MEMORY_BLOCK
    assert "AFTER completing" not in _MEMORY_BLOCK


def test_memory_section_gated_on_all_tools():
    """_memory_section returns _MEMORY_BLOCK only when recall_entity is in ALL_TOOLS."""
    with patch("core.llm.tool_schemas.ALL_TOOLS", [{"name": "list_findings"}]):
        assert _memory_section() == ""

    with patch(
        "core.llm.tool_schemas.ALL_TOOLS",
        [{"name": "list_findings"}, {"name": "recall_entity"}],
    ):
        assert _memory_section() == _MEMORY_BLOCK


def test_render_base_prompt_includes_memory_when_recall_in_all_tools():
    """render_base_prompt includes the memory block if recall_entity is in ALL_TOOLS."""
    with patch("core.llm.tool_schemas.ALL_TOOLS", [{"name": "list_findings"}]):
        prompt_without = render_base_prompt(role="Triage Agent")
        assert "<memory_operations>" not in prompt_without

    with patch(
        "core.llm.tool_schemas.ALL_TOOLS",
        [{"name": "list_findings"}, {"name": "recall_entity"}],
    ):
        prompt_with = render_base_prompt(role="Triage Agent")
        assert "<memory_operations>" in prompt_with
        assert "recall_entity" in prompt_with
        assert "do not write to memory" in prompt_with


def test_builtin_principles_memory_lines_are_read_only():
    """Every builtin agent's extra_principles Memory line instructs read-only recall_entity."""
    forbidden_phrases = [
        "mempalace_add_drawer",
        "mempalace_diary_write",
        "mempalace_kg_add",
        "store FP reasoning",
        "mempalace_search",
    ]
    for agent in BUILTIN_AGENTS:
        principles = agent.get("extra_principles", "")
        for phrase in forbidden_phrases:
            assert (
                phrase not in principles
            ), f"Agent {agent['id']} has '{phrase}' in extra_principles"

        # Every agent should have a Memory: principle directing recall_entity
        assert (
            "Memory: recall_entity" in principles
        ), f"Agent {agent['id']} missing 'Memory: recall_entity' in extra_principles"
        assert (
            "do not write to memory" in principles
        ), f"Agent {agent['id']} missing 'do not write to memory' in extra_principles"


@pytest.mark.parametrize(
    "workflow_name",
    ["incident-response", "full-investigation", "forensic-analysis", "cloud-incident"],
)
def test_compose_workflows_grant_recall_entity_in_all_phases(workflow_name: str):
    """All phases in compose workflows must include recall_entity in tools list (#735)."""
    workflow_path = (
        REPO
        / "core"
        / "workflows"
        / "definitions"
        / workflow_name
        / "WORKFLOW.md"
    )
    content = workflow_path.read_text()
    # Frontmatter is between the first two --- delimiters
    parts = content.split("---", 2)
    assert len(parts) >= 3, f"Invalid frontmatter in {workflow_name}"
    data = yaml.safe_load(parts[1])

    phases = data.get("phases", [])
    assert len(phases) > 0, f"No phases found in {workflow_name}"
    for phase in phases:
        tools = phase.get("tools", [])
        assert (
            "recall_entity" in tools
        ), f"Workflow '{workflow_name}' phase '{phase['id']}' missing recall_entity in tools: {tools}"
