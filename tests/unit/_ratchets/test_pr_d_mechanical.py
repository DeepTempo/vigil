"""Unit tests for the PR-D mechanical optimizations (GH #84).

Covers four small helpers introduced to drive down token spend:
  1. ``ClaudeService._filter_tools_by_name`` — per-agent tool filtering
  2. ``ClaudeService._apply_history_window`` — sliding-window conversation history
  3. ``ClaudeService._truncate_tool_response`` + ``TOOL_RESPONSE_BUDGETS`` — tiered tool-result truncation
  4. ``AgentProfile.thinking_budget`` — per-agent extended-thinking budgets
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO))

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# 1. Per-agent tool filtering
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 2. Sliding-window history
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 3. Tiered tool-result truncation
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 4. Per-agent thinking_budget
# ---------------------------------------------------------------------------


class TestAgentProfileThinkingBudget:
    def test_thinking_agent_has_budget(self):
        from core.agents.manager import SOCAgentLibrary

        agents = SOCAgentLibrary.get_all_agents()
        # Investigator is a deep-reasoning agent — should have a budget set.
        profile = agents["investigator"]
        assert profile.enable_thinking is True
        assert profile.thinking_budget is not None
        assert profile.thinking_budget >= 4000

    def test_auto_responder_budget_is_trimmed(self):
        """auto_responder runs high-confidence pre-approved actions —
        budget should be deliberately small to prevent cost drift."""
        from core.agents.manager import SOCAgentLibrary

        agents = SOCAgentLibrary.get_all_agents()
        profile = agents["auto_responder"]
        assert profile.enable_thinking is True
        assert profile.thinking_budget is not None
        assert profile.thinking_budget <= 5000

    def test_non_thinking_agent_has_no_budget(self):
        """Agents with thinking disabled shouldn't carry a budget."""
        from core.agents.manager import SOCAgentLibrary

        agents = SOCAgentLibrary.get_all_agents()
        profile = agents["triage"]
        assert profile.enable_thinking is False
        assert profile.thinking_budget is None

    def test_custom_agent_picks_up_budget_from_row(self):
        from core.agents.manager import SOCAgentLibrary

        profile = SOCAgentLibrary.build_profile(
            {
                "id": "custom-1",
                "name": "Custom",
                "enable_thinking": True,
                "thinking_budget": 4096,
            }
        )
        assert profile.thinking_budget == 4096


# ---------------------------------------------------------------------------
# 5. Daemon agent_runner default budget
# ---------------------------------------------------------------------------


# TestDaemonDefaultThinkingBudget dropped with agent_runner (#629). The helper
# was the runner's, and the run's ceilings are the budget seam's now. The
# thinking_budget system_config row it read has no consumer left -- ADR 0011
# carries no thinking blocks -- so retiring the setting belongs to #642.
#
# Dropped with the helpers these covered (#631), and where the guarantee moved:
#
# TestFilterToolsByName — a role sees what the arch granted it, deny by default,
#   rather than a catalogue filtered after the fact. See the registry and
#   services/agent/tests/core/stream.test.ts, "refuses a tool the role was not
#   granted without stopping the loop".
#
# TestApplyHistoryWindow — a flat tail window is replaced by a fold that holds
#   both edges and never strands a tool result. See
#   services/agent/tests/core/context.test.ts.
#
# TestTieredTruncation — per-tool response budgets are one result_cap applied at
#   the single place a result is rendered. See core/security.ts and
#   services/agent/tests/core/security.test.ts.
