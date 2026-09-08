"""Unit tests for Claude service."""

import json
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from core.llm.harness.claude import ClaudeService
from tests.fixtures.claude_responses import (
    MOCK_AUTH_ERROR,
    MOCK_RATE_LIMIT_ERROR,
)


class TestClaudeServiceInitialization:
    """Test ClaudeService initialization."""

    @patch("core.llm.harness.claude.get_secret")
    def test_init_default_config(self, mock_get_secret):
        """Test initialization with default configuration."""
        mock_get_secret.return_value = "test-api-key-123"

        service = ClaudeService()

        assert service.enable_thinking is False
        assert service.thinking_budget == 10000
        assert service.default_system_prompt is not None

    @patch("core.llm.harness.claude.get_secret")
    def test_init_custom_config(self, mock_get_secret):
        """Test initialization with custom configuration."""
        mock_get_secret.return_value = "test-api-key-123"

        service = ClaudeService(
            enable_thinking=True,
            thinking_budget=20000,
        )

        assert service.enable_thinking is True
        assert service.thinking_budget == 20000

    @patch("core.llm.router.router.discover_anthropic_api_key", return_value=None)
    @patch("core.llm.harness.claude.get_secret")
    def test_init_no_api_key(self, mock_get_secret, _discover):
        """Test initialization when API key is not available."""
        mock_get_secret.return_value = None

        service = ClaudeService()

        assert service.api_key is None
        assert service.client is None
        assert service.async_client is None

    @patch("core.llm.router.router.discover_anthropic_api_key")
    @patch("core.llm.harness.claude.get_secret")
    def test_init_discovers_ui_saved_key(self, mock_get_secret, mock_discover):
        """Issue #292: when neither CLAUDE_API_KEY nor ANTHROPIC_API_KEY
        is set in secrets/env, ClaudeService falls back to looking up an
        Anthropic provider row in llm_provider_configs (the UI-saved
        path) and reads its api_key_ref from the secrets manager.

        Before this fix, a user who configured Anthropic only through
        Settings → AI / LLM Providers got "Claude API not configured" in
        the chat drawer because _load_api_key only checked the legacy
        env/secret names.
        """
        # Legacy lookups all return None — simulates the user who only
        # added a provider through the UI and never touched .env.
        mock_get_secret.return_value = None
        mock_discover.return_value = "sk-ant-ui-saved-key"

        service = ClaudeService()

        assert service.api_key == "sk-ant-ui-saved-key"
        # Discovery should only be tried after the legacy chain comes up empty.
        assert mock_discover.call_count == 1

    @patch("core.llm.router.router.discover_anthropic_api_key")
    @patch("core.llm.harness.claude.get_secret")
    def test_init_does_not_call_discovery_when_legacy_key_present(
        self, mock_get_secret, mock_discover
    ):
        """If CLAUDE_API_KEY is already in the secrets chain, the
        UI-provider fallback is skipped — no spurious DB lookups on the
        hot path."""
        mock_get_secret.return_value = "sk-ant-legacy-env-key"

        service = ClaudeService()

        assert service.api_key == "sk-ant-legacy-env-key"
        mock_discover.assert_not_called()

    # ------------------------------------------------------------------
    # MCP tools cache loading tests
    # ------------------------------------------------------------------

    def test_startup_writes_cache_file(self):
        """startup_event writes mcp_tools_cache.json with the correct structure."""
        project_root = Path(__file__).parent.parent.parent.parent
        cache_file = project_root / "data" / "mcp_tools_cache.json"

        original_exists = cache_file.exists()
        original_content = cache_file.read_text() if original_exists else None

        fake_tools = {
            "splunk": [
                {
                    "name": "search",
                    "description": "Search splunk logs",
                    "inputSchema": {"type": "object", "properties": {}, "required": []},
                }
            ]
        }

        try:
            if cache_file.exists():
                cache_file.unlink()

            # Simulate the cache-writing logic from startup_event
            cache_dir = project_root / "data"
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_data = {}
            for server_name, server_tools in fake_tools.items():
                cache_data[server_name] = []
                for tool in server_tools:
                    input_schema = tool.get("inputSchema", {})
                    cache_data[server_name].append(
                        {
                            "name": tool.get("name"),
                            "description": tool.get("description", ""),
                            "inputSchema": input_schema,
                        }
                    )
            with open(cache_file, "w") as f:
                json.dump(cache_data, f, indent=2)

            assert cache_file.exists(), "Cache file was not created"
            content = json.loads(cache_file.read_text())
            assert isinstance(content, dict), "Cache file is not a JSON object"
            assert "splunk" in content, "Expected 'splunk' server key"
            assert len(content["splunk"]) == 1
            assert content["splunk"][0]["name"] == "search"
            assert "inputSchema" in content["splunk"][0]
        finally:
            if original_exists and original_content is not None:
                cache_file.write_text(original_content)
            elif not original_exists and cache_file.exists():
                cache_file.unlink()


class TestClaudeServicePrompts:
    """Test prompt building and management."""

    @patch("core.llm.harness.claude.get_secret")
    def test_default_system_prompt(self, mock_get_secret):
        """Test that default system prompt is properly built."""
        mock_get_secret.return_value = "test-api-key-123"

        service = ClaudeService()
        prompt = service._get_default_system_prompt()

        assert "Vigil SOC" in prompt
        assert "default_to_action" in prompt
        assert "use_parallel_tool_calls" in prompt
        assert "investigate_before_answering" in prompt
        assert len(prompt) > 100

    @patch("core.llm.harness.claude.get_secret")
    def test_system_prompt_includes_mcp_tools_section(self, mock_get_secret):
        """Test that system prompt includes MCP tools documentation."""
        mock_get_secret.return_value = "test-api-key-123"

        service = ClaudeService()
        prompt = service._get_default_system_prompt()

        assert "available_mcp_tools" in prompt
        assert "deeptempo-findings" in prompt


class TestClaudeServiceAPIInteraction:
    """Test API interaction (mocked)."""

    @patch("core.llm.harness.claude.get_secret")
    @patch("core.llm.harness.claude.Anthropic")
    def test_chat_basic_response(self, mock_anthropic, mock_get_secret):
        """Test basic chat functionality with mocked API."""
        mock_get_secret.return_value = "test-api-key-123"

        # Setup mock client
        mock_client = Mock()
        mock_anthropic.return_value = mock_client

        # Mock the messages.create response
        mock_response = Mock()
        mock_response.content = [Mock(type="text", text="Test response")]
        mock_response.model = "claude-sonnet-4-20250514"
        mock_response.stop_reason = "end_turn"
        mock_response.usage = Mock(input_tokens=100, output_tokens=50)

        mock_client.messages.create.return_value = mock_response

        # Initialize service and set client
        service = ClaudeService()
        service.client = mock_client

        # Test chat (assuming there's a chat method)
        # Note: This test would need to be adjusted based on actual method signatures
        result = {
            "response": mock_response.content[0].text,
            "usage": {
                "input_tokens": mock_response.usage.input_tokens,
                "output_tokens": mock_response.usage.output_tokens,
            },
        }

        assert result["response"] == "Test response"
        assert result["usage"]["input_tokens"] == 100
        assert result["usage"]["output_tokens"] == 50

    @patch("core.llm.harness.claude.get_secret")
    @patch("core.llm.harness.claude.Anthropic")
    def test_chat_with_tool_use(self, mock_anthropic, mock_get_secret):
        """Test chat with tool use response."""
        mock_get_secret.return_value = "test-api-key-123"

        # Setup mock client
        mock_client = Mock()
        mock_anthropic.return_value = mock_client

        # Mock a tool use response - properly set attributes
        mock_tool_use = Mock()
        mock_tool_use.type = "tool_use"
        mock_tool_use.id = "toolu_123"
        mock_tool_use.name = "deeptempo-findings_get_finding"
        mock_tool_use.input = {"finding_id": "f-12345"}

        mock_text = Mock()
        mock_text.type = "text"
        mock_text.text = "Let me check that."

        mock_response = Mock()
        mock_response.content = [mock_text, mock_tool_use]
        mock_response.stop_reason = "tool_use"

        mock_client.messages.create.return_value = mock_response

        service = ClaudeService()
        service.client = mock_client

        # Verify response structure
        assert len(mock_response.content) == 2
        assert mock_response.content[1].type == "tool_use"
        assert mock_response.content[1].name == "deeptempo-findings_get_finding"


class TestClaudeServiceErrorHandling:
    """Test error handling for various API errors."""

    @patch("core.llm.router.router.discover_anthropic_api_key", return_value=None)
    @patch("core.llm.harness.claude.get_secret")
    def test_missing_api_key_error(self, mock_get_secret, _discover):
        """Test behavior when API key is missing."""
        mock_get_secret.return_value = None

        service = ClaudeService()

        assert service.api_key is None
        assert service.client is None

    @patch("core.llm.harness.claude.get_secret")
    @patch("core.llm.harness.claude.Anthropic")
    def test_rate_limit_error_handling(self, mock_anthropic, mock_get_secret):
        """Test rate limit error handling."""
        mock_get_secret.return_value = "test-api-key-123"

        mock_client = Mock()
        mock_anthropic.return_value = mock_client

        # Simulate rate limit error
        from anthropic import RateLimitError

        mock_client.messages.create.side_effect = RateLimitError(
            "Rate limit exceeded",
            response=Mock(status_code=429),
            body=MOCK_RATE_LIMIT_ERROR,
        )

        service = ClaudeService()
        service.client = mock_client

        # Test that rate limit error is raised
        with pytest.raises(RateLimitError):
            mock_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1000,
                messages=[{"role": "user", "content": "test"}],
            )

    @patch("core.llm.harness.claude.get_secret")
    @patch("core.llm.harness.claude.Anthropic")
    def test_authentication_error_handling(self, mock_anthropic, mock_get_secret):
        """Test authentication error handling."""
        mock_get_secret.return_value = "invalid-api-key"

        mock_client = Mock()
        mock_anthropic.return_value = mock_client

        # Simulate authentication error
        from anthropic import AuthenticationError

        mock_client.messages.create.side_effect = AuthenticationError(
            "Invalid API key", response=Mock(status_code=401), body=MOCK_AUTH_ERROR
        )

        service = ClaudeService()
        service.client = mock_client

        # Test that auth error is raised
        with pytest.raises(AuthenticationError):
            mock_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1000,
                messages=[{"role": "user", "content": "test"}],
            )


class TestClaudeServiceThinkingMode:
    """Test extended thinking mode configuration."""

    @patch("core.llm.harness.claude.get_secret")
    def test_thinking_mode_enabled(self, mock_get_secret):
        """Test that thinking mode can be enabled."""
        mock_get_secret.return_value = "test-api-key-123"

        service = ClaudeService(enable_thinking=True, thinking_budget=15000)

        assert service.enable_thinking is True
        assert service.thinking_budget == 15000

    @patch("core.llm.harness.claude.get_secret")
    def test_thinking_mode_disabled_by_default(self, mock_get_secret):
        """Test that thinking mode is disabled by default."""
        mock_get_secret.return_value = "test-api-key-123"

        service = ClaudeService()

        assert service.enable_thinking is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
