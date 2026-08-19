"""Unit tests for core.platform.runtime_config (GH #84 PR-F).

Covers the DB → env → default resolution order and the in-process cache
behavior used by ClaudeService / AgentRunner consumers.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO))

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_cache():
    """Every test starts with a clean runtime-config cache."""
    from core.platform import runtime_config

    runtime_config.clear_cache()
    yield
    runtime_config.clear_cache()


class TestResolutionOrder:
    def test_db_value_wins_over_env(self, monkeypatch):
        from core.platform import runtime_config

        monkeypatch.setenv("CLAUDE_HISTORY_WINDOW", "5")
        with patch.object(
            runtime_config, "_fetch_db_config", return_value={"history_window": 42}
        ):
            assert runtime_config.get_ai_operations_setting("history_window", 20) == 42

    def test_env_wins_when_db_missing(self, monkeypatch):
        from core.platform import runtime_config

        monkeypatch.setenv("CLAUDE_HISTORY_WINDOW", "7")
        with patch.object(runtime_config, "_fetch_db_config", return_value={}):
            assert runtime_config.get_ai_operations_setting("history_window", 20) == 7

    def test_default_when_nothing_set(self, monkeypatch):
        from core.platform import runtime_config

        monkeypatch.delenv("CLAUDE_HISTORY_WINDOW", raising=False)
        with patch.object(runtime_config, "_fetch_db_config", return_value={}):
            assert runtime_config.get_ai_operations_setting("history_window", 20) == 20

    def test_db_fetch_failure_falls_through_to_env(self, monkeypatch):
        from core.platform import runtime_config

        monkeypatch.setenv("CLAUDE_HISTORY_WINDOW", "11")
        # _fetch_db_config returning None (our convention for "DB unavailable")
        # still lets env/default win.
        with patch.object(runtime_config, "_fetch_db_config", return_value=None):
            assert runtime_config.get_ai_operations_setting("history_window", 20) == 11

    def test_unknown_key_skips_env_lookup(self, monkeypatch):
        """Keys not in ENV_FALLBACKS go straight to default — no risk of a
        typo silently reading an unrelated env var."""
        from core.platform import runtime_config

        monkeypatch.setenv("NONSENSE_KEY", "99")
        with patch.object(runtime_config, "_fetch_db_config", return_value={}):
            assert runtime_config.get_ai_operations_setting("nonsense_key", 5) == 5


class TestTypeCoercion:
    def test_bool_from_string(self, monkeypatch):
        from core.platform import runtime_config

        monkeypatch.setenv("ANTHROPIC_PROMPT_CACHE_ENABLED", "false")
        with patch.object(runtime_config, "_fetch_db_config", return_value={}):
            assert (
                runtime_config.get_ai_operations_setting("prompt_cache_enabled", True)
                is False
            )

    def test_bool_preserved_from_db(self):
        from core.platform import runtime_config

        with patch.object(
            runtime_config,
            "_fetch_db_config",
            return_value={"prompt_cache_enabled": False},
        ):
            assert (
                runtime_config.get_ai_operations_setting("prompt_cache_enabled", True)
                is False
            )

    def test_int_coerced_from_env_string(self, monkeypatch):
        from core.platform import runtime_config

        monkeypatch.setenv("CLAUDE_THINKING_BUDGET", "4096")
        with patch.object(runtime_config, "_fetch_db_config", return_value={}):
            assert (
                runtime_config.get_ai_operations_setting("thinking_budget", 10000)
                == 4096
            )

    def test_bad_int_falls_back_to_default(self, monkeypatch):
        from core.platform import runtime_config

        monkeypatch.setenv("CLAUDE_THINKING_BUDGET", "not-a-number")
        with patch.object(runtime_config, "_fetch_db_config", return_value={}):
            assert (
                runtime_config.get_ai_operations_setting("thinking_budget", 10000)
                == 10000
            )

    def test_local_recovery_uses_its_own_env_fallback(self, monkeypatch):
        from core.platform import runtime_config

        monkeypatch.setenv("LOCAL_OLLAMA_RECOVERY_RETRY_LIMIT", "2")
        with patch.object(runtime_config, "_fetch_db_config", return_value={}):
            assert (
                runtime_config.get_ai_operations_setting(
                    "local_ollama_recovery_retry_limit", 1
                )
                == 2
            )

    def test_local_recovery_enabled_bool_env_fallback(self, monkeypatch):
        from core.platform import runtime_config

        monkeypatch.setenv("LOCAL_OLLAMA_RECOVERY_ENABLED", "false")
        with patch.object(runtime_config, "_fetch_db_config", return_value={}):
            assert (
                runtime_config.get_ai_operations_setting(
                    "local_ollama_recovery_enabled", True
                )
                is False
            )

    def test_local_recovery_restart_bool_env_fallback(self, monkeypatch):
        from core.platform import runtime_config

        monkeypatch.setenv("LOCAL_OLLAMA_RECOVERY_RESTART_GATEWAY", "false")
        with patch.object(runtime_config, "_fetch_db_config", return_value={}):
            assert (
                runtime_config.get_ai_operations_setting(
                    "local_ollama_recovery_restart_gateway", True
                )
                is False
            )


class TestAIOperationsSettingsModel:
    """The Settings-UI config model must expose the local-recovery toggles
    with safe defaults and clamp the retry limit to the documented range."""

    def test_defaults_include_local_recovery_toggles(self):
        from services.api.routers.config import AI_OPERATIONS_DEFAULTS

        assert AI_OPERATIONS_DEFAULTS["local_ollama_recovery_enabled"] is True
        assert AI_OPERATIONS_DEFAULTS["local_ollama_recovery_retry_limit"] == 1
        assert AI_OPERATIONS_DEFAULTS["local_ollama_recovery_restart_gateway"] is True

    def test_retry_limit_rejects_out_of_range(self):
        from pydantic import ValidationError

        from services.api.routers.config import AIOperationsSettingsConfig

        with pytest.raises(ValidationError):
            AIOperationsSettingsConfig(local_ollama_recovery_retry_limit=5)
        with pytest.raises(ValidationError):
            AIOperationsSettingsConfig(local_ollama_recovery_retry_limit=-1)


class TestCacheBehavior:
    def test_cache_avoids_repeated_db_fetch(self):
        from core.platform import runtime_config

        fetch_mock = patch.object(
            runtime_config,
            "_fetch_db_config",
            return_value={"history_window": 15},
        )
        with fetch_mock as m:
            runtime_config.get_ai_operations_setting("history_window", 20)
            runtime_config.get_ai_operations_setting("history_window", 20)
            runtime_config.get_ai_operations_setting("thinking_budget", 10000)
            # Three reads, one DB fetch (cache holds the dict).
            assert m.call_count == 1

    def test_clear_cache_triggers_refetch(self):
        from core.platform import runtime_config

        with patch.object(
            runtime_config, "_fetch_db_config", return_value={"history_window": 3}
        ) as m:
            runtime_config.get_ai_operations_setting("history_window", 20)
            runtime_config.clear_cache()
            runtime_config.get_ai_operations_setting("history_window", 20)
            assert m.call_count == 2


class TestConsumerIntegration:
    """End-to-end checks that the ClaudeService / AgentRunner helpers now
    honor the DB-backed settings, not just env vars.
    """


# Three consumers dropped with the helpers they exercised (#631). The plumbing
# they went through -- DB over env over default, coercion, caching -- is covered
# above and unchanged; only these consumers moved:
#
#   thinking_budget      -> nobody. agent_runner held the only consumer and is
#                           gone with #629; retiring the setting is #642.
#   history_window       -> the fold in services/agent/core/context.ts, which
#                           holds both edges instead of keeping a flat tail.
#   prompt_cache_enabled -> nothing. ADR 0011 traded cache_control away: the
#                           OpenAI surface caches on a byte-identical prefix, so
#                           there is no marker to place and no switch to kill.
#   tool_response_budget -> result_cap, applied where a result is rendered.
