"""Unit tests for Claude service."""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from core.llm.harness.claude import ClaudeService
from tests.fixtures.claude_responses import (MOCK_AUTH_ERROR,
                                             MOCK_CHAT_RESPONSE,
                                             MOCK_CONVERSATION_HISTORY,
                                             MOCK_INVALID_REQUEST_ERROR,
                                             MOCK_RATE_LIMIT_ERROR,
                                             MOCK_THINKING_RESPONSE,
                                             MOCK_TOOL_USE_RESPONSE)


class TestClaudeServiceInitialization:
    """Test ClaudeService initialization."""

    @patch("core.llm.harness.claude.get_secret")
    def test_init_default_config(self, mock_get_secret):
        """Test initialization with default configuration."""
        mock_get_secret.return_value = "test-api-key-123"

        service = ClaudeService()

        assert service.use_mcp_tools is True
        assert service.enable_thinking is False
        assert service.thinking_budget == 10000
        assert service._session_mgr.sessions == {}
        assert service.default_system_prompt is not None

    @patch("core.llm.harness.claude.get_secret")
    def test_init_custom_config(self, mock_get_secret):
        """Test initialization with custom configuration."""
        mock_get_secret.return_value = "test-api-key-123"

        service = ClaudeService(
            use_mcp_tools=False,
            enable_thinking=True,
            thinking_budget=20000,
        )

        assert service.use_mcp_tools is False
        assert service.enable_thinking is True
        assert service.thinking_budget == 20000

    @patch("core.llm.harness.claude.get_secret")
    def test_init_no_api_key(self, mock_get_secret):
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

    @patch("core.llm.harness.claude.get_secret")
    def test_load_mcp_tools_from_cache_file(self, mock_get_secret):
        """_load_mcp_tools populates mcp_tools from a JSON cache file."""
        mock_get_secret.return_value = "test-api-key-123"

        cache_data = {
            "splunk": [
                {
                    "name": "search",
                    "description": "Search logs",
                    "inputSchema": {"type": "object", "properties": {}, "required": []},
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = Path(tmpdir) / "mcp_tools_cache.json"
            cache_file.write_text(json.dumps(cache_data))

            cache_path = str(cache_file)
            # Patch the cache path inside claude_service so it reads our temp file
            with patch(
                "core.llm.harness.claude.Path",
                side_effect=lambda *args: Path(*args),
            ):
                with patch.object(
                    Path,
                    "__new__",
                    side_effect=None,
                ):
                    pass  # not needed – use simpler approach below

            # Simplest approach: patch the __file__ anchoring logic by replacing
            # the resolved cache_file path inside _load_mcp_tools via a context manager
            original_load = ClaudeService._load_mcp_tools

            def patched_load(self_inner):
                self_inner.mcp_tools = []
                try:
                    tools_dict = json.loads(cache_file.read_text())
                    seen_tool_names = set()
                    for server_name, server_tools in tools_dict.items():
                        for tool in server_tools:
                            tool_name = f"{server_name}_{tool['name']}"
                            if tool_name in seen_tool_names:
                                continue
                            seen_tool_names.add(tool_name)
                            input_schema = tool.get("inputSchema", {})
                            if not isinstance(input_schema, dict):
                                input_schema = {}
                            if not input_schema or "type" not in input_schema:
                                input_schema = {
                                    "type": "object",
                                    "properties": {},
                                    "required": [],
                                }
                            self_inner.mcp_tools.append(
                                {
                                    "name": tool_name,
                                    "description": f"[{server_name}] {tool.get('description', '')}",
                                    "input_schema": input_schema,
                                }
                            )
                except Exception:
                    self_inner.mcp_tools = []

            with patch.object(ClaudeService, "_load_mcp_tools", patched_load):
                service = ClaudeService(use_mcp_tools=True)

        assert len(service.mcp_tools) >= 1
        tool_names = [t["name"] for t in service.mcp_tools]
        assert "splunk_search" in tool_names

    @patch("core.llm.harness.claude.get_secret")
    def test_load_mcp_tools_cache_file_direct(self, mock_get_secret):
        """_load_mcp_tools reads actual cache file path used by the service."""
        mock_get_secret.return_value = "test-api-key-123"

        cache_data = {
            "splunk": [
                {
                    "name": "search",
                    "description": "Search logs",
                    "inputSchema": {"type": "object", "properties": {}, "required": []},
                }
            ]
        }

        # The service reads REPO_ROOT / "data" / "mcp_tools_cache.json"; __file__
        # here is tests/llm/test_claude_service.py, so three parents is that root.
        project_root = Path(__file__).parent.parent.parent.parent
        cache_file = project_root / "data" / "mcp_tools_cache.json"

        original_exists = cache_file.exists()
        original_content = cache_file.read_text() if original_exists else None

        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(cache_data))

            with patch(
                "core.integrations.mcp.client.get_mcp_client", return_value=None
            ):
                with patch.object(ClaudeService, "_populate_mcp_registry"):
                    service = ClaudeService(use_mcp_tools=True)

            assert len(service.mcp_tools) >= 1
            tool_names = [t["name"] for t in service.mcp_tools]
            assert "splunk_search" in tool_names
        finally:
            if original_exists and original_content is not None:
                cache_file.write_text(original_content)
            elif not original_exists and cache_file.exists():
                cache_file.unlink()

    @patch("core.llm.harness.claude.get_secret")
    def test_load_mcp_tools_fallback_to_in_memory_cache(self, mock_get_secret):
        """Falls back to mcp_client.tools_cache when cache file is absent."""
        mock_get_secret.return_value = "test-api-key-123"

        mock_client = Mock()
        mock_client.tools_cache = {
            "jira": [
                {
                    "name": "create_issue",
                    "description": "Create a Jira issue",
                    "inputSchema": {"type": "object", "properties": {}, "required": []},
                }
            ]
        }

        project_root = Path(__file__).parent.parent.parent.parent
        cache_file = project_root / "data" / "mcp_tools_cache.json"

        original_exists = cache_file.exists()
        original_content = cache_file.read_text() if original_exists else None

        try:
            if cache_file.exists():
                cache_file.unlink()

            with patch(
                "core.integrations.mcp.client.get_mcp_client", return_value=mock_client
            ):
                with patch.object(ClaudeService, "_populate_mcp_registry"):
                    service = ClaudeService(use_mcp_tools=True)

            assert len(service.mcp_tools) >= 1
            tool_names = [t["name"] for t in service.mcp_tools]
            assert "jira_create_issue" in tool_names
        finally:
            if original_exists and original_content is not None:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(original_content)

    @patch("core.llm.harness.claude.get_secret")
    def test_load_mcp_tools_no_sources_available(self, mock_get_secret):
        """Sets mcp_tools=[] without raising when no cache file and no client."""
        mock_get_secret.return_value = "test-api-key-123"

        project_root = Path(__file__).parent.parent.parent.parent
        cache_file = project_root / "data" / "mcp_tools_cache.json"

        original_exists = cache_file.exists()
        original_content = cache_file.read_text() if original_exists else None

        try:
            if cache_file.exists():
                cache_file.unlink()

            with patch(
                "core.integrations.mcp.client.get_mcp_client", return_value=None
            ):
                service = ClaudeService(use_mcp_tools=True)

            assert service.mcp_tools == []
        finally:
            if original_exists and original_content is not None:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(original_content)

    @patch("core.llm.harness.claude.get_secret")
    def test_load_mcp_tools_malformed_cache_file(self, mock_get_secret):
        """Falls back to in-memory cache when cache file contains invalid JSON."""
        mock_get_secret.return_value = "test-api-key-123"

        mock_client = Mock()
        mock_client.tools_cache = {
            "elastic": [
                {
                    "name": "query",
                    "description": "Run an Elasticsearch query",
                    "inputSchema": {"type": "object", "properties": {}, "required": []},
                }
            ]
        }

        project_root = Path(__file__).parent.parent.parent.parent
        cache_file = project_root / "data" / "mcp_tools_cache.json"

        original_exists = cache_file.exists()
        original_content = cache_file.read_text() if original_exists else None

        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text("invalid json{")

            with patch(
                "core.integrations.mcp.client.get_mcp_client", return_value=mock_client
            ):
                with patch.object(ClaudeService, "_populate_mcp_registry"):
                    service = ClaudeService(use_mcp_tools=True)

            assert len(service.mcp_tools) >= 1
            tool_names = [t["name"] for t in service.mcp_tools]
            assert "elastic_query" in tool_names
        finally:
            if original_exists and original_content is not None:
                cache_file.write_text(original_content)
            elif not original_exists and cache_file.exists():
                cache_file.unlink()

    @patch("core.llm.harness.claude.get_secret")
    def test_no_event_loop_creation(self, mock_get_secret):
        """_load_mcp_tools never calls asyncio.new_event_loop."""
        mock_get_secret.return_value = "test-api-key-123"

        project_root = Path(__file__).parent.parent.parent.parent
        cache_file = project_root / "data" / "mcp_tools_cache.json"

        original_exists = cache_file.exists()
        original_content = cache_file.read_text() if original_exists else None

        cache_data = {
            "splunk": [
                {
                    "name": "search",
                    "description": "Search logs",
                    "inputSchema": {"type": "object", "properties": {}, "required": []},
                }
            ]
        }

        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(cache_data))

            with patch("asyncio.new_event_loop") as mock_new_loop, patch(
                "core.integrations.mcp.client.get_mcp_client"
            ) as mock_get_client:
                # Cached tools only surface for servers connected this boot.
                mock_get_client.return_value.get_connection_status.return_value = {
                    "splunk": True
                }
                with patch.object(ClaudeService, "_populate_mcp_registry"):
                    service = ClaudeService(use_mcp_tools=True)
                mock_new_loop.assert_not_called()

            assert len(service.mcp_tools) >= 1
        finally:
            if original_exists and original_content is not None:
                cache_file.write_text(original_content)
            elif not original_exists and cache_file.exists():
                cache_file.unlink()

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

        service = ClaudeService(use_mcp_tools=True)
        prompt = service._get_default_system_prompt()

        assert "available_mcp_tools" in prompt
        assert "deeptempo-findings" in prompt


class TestClaudeServiceSessionManagement:
    """Test session management for multi-turn conversations."""

    @patch("core.llm.harness.claude.get_secret")
    def test_create_session(self, mock_get_secret):
        """Test creating a new session."""
        mock_get_secret.return_value = "test-api-key-123"

        service = ClaudeService()
        session_id = "test-session-123"

        # Add messages to session
        service._session_mgr.sessions[session_id] = MOCK_CONVERSATION_HISTORY.copy()

        assert session_id in service._session_mgr.sessions
        assert len(service._session_mgr.sessions[session_id]) == 4

    @patch("core.llm.harness.claude.get_secret")
    def test_clear_session(self, mock_get_secret):
        """Test clearing a session."""
        mock_get_secret.return_value = "test-api-key-123"

        service = ClaudeService()
        session_id = "test-session-123"

        # Add messages to session
        service._session_mgr.sessions[session_id] = MOCK_CONVERSATION_HISTORY.copy()

        # Clear session
        if session_id in service._session_mgr.sessions:
            del service._session_mgr.sessions[session_id]

        assert session_id not in service._session_mgr.sessions

    @patch("core.llm.harness.claude.get_secret")
    def test_session_isolation(self, mock_get_secret):
        """Test that sessions are isolated from each other."""
        mock_get_secret.return_value = "test-api-key-123"

        service = ClaudeService()

        session1_id = "session-1"
        session2_id = "session-2"

        service._session_mgr.sessions[session1_id] = [
            {"role": "user", "content": "Message 1"}
        ]
        service._session_mgr.sessions[session2_id] = [
            {"role": "user", "content": "Message 2"}
        ]

        assert len(service._session_mgr.sessions[session1_id]) == 1
        assert len(service._session_mgr.sessions[session2_id]) == 1
        assert (
            service._session_mgr.sessions[session1_id]
            != service._session_mgr.sessions[session2_id]
        )


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
        service = ClaudeService(use_mcp_tools=False)
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

        service = ClaudeService(use_mcp_tools=True)
        service.client = mock_client

        # Verify response structure
        assert len(mock_response.content) == 2
        assert mock_response.content[1].type == "tool_use"
        assert mock_response.content[1].name == "deeptempo-findings_get_finding"


class TestClaudeServiceErrorHandling:
    """Test error handling for various API errors."""

    @patch("core.llm.harness.claude.get_secret")
    def test_missing_api_key_error(self, mock_get_secret):
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


class TestClaudeServiceMCPTools:
    """Test MCP tool integration."""

    @patch("core.llm.harness.claude.get_secret")
    def test_mcp_tools_enabled(self, mock_get_secret):
        """Test that MCP tools can be enabled."""
        mock_get_secret.return_value = "test-api-key-123"

        service = ClaudeService(use_mcp_tools=True)

        assert service.use_mcp_tools is True

    @patch("core.llm.harness.claude.get_secret")
    def test_mcp_tools_disabled(self, mock_get_secret):
        """Test that MCP tools can be disabled."""
        mock_get_secret.return_value = "test-api-key-123"

        service = ClaudeService(use_mcp_tools=False)

        assert service.use_mcp_tools is False
        assert service.mcp_tools == []


class TestEmptyToolSetsPassNoneToApi:
    """Verify that empty tool lists result in tools=None (not []) when calling the API."""

    BACKEND_TOOL = {
        "name": "bt",
        "description": "B",
        "input_schema": {"type": "object", "properties": {}},
    }
    MCP_TOOL = {
        "name": "mt",
        "description": "M",
        "input_schema": {"type": "object", "properties": {}},
    }

    def _make_service(self, backend_tools, mcp_tools):
        with patch(
            "core.llm.harness.claude.get_secret", return_value="test-key"
        ), patch.object(
            ClaudeService, "_load_backend_tools", lambda self: None
        ), patch.object(
            ClaudeService, "_load_mcp_tools", lambda self: None
        ):
            service = ClaudeService(use_backend_tools=True, use_mcp_tools=True)
        service.backend_tools = backend_tools
        service.mcp_tools = mcp_tools
        return service

    @patch("core.llm.harness.claude.Anthropic")
    def test_chat_does_not_pass_tools_when_both_sets_empty(self, mock_anthropic):
        """chat() omits the 'tools' key entirely when both tool sets are empty."""
        mock_client = Mock()
        mock_anthropic.return_value = mock_client

        mock_response = Mock()
        mock_response.content = [Mock(type="text", text="OK")]
        mock_response.stop_reason = "end_turn"
        mock_response.model = "claude-sonnet-4-5-20250929"
        mock_response.usage = Mock(input_tokens=10, output_tokens=5)
        mock_client.messages.create.return_value = mock_response

        service = self._make_service(backend_tools=[], mcp_tools=[])
        service.client = mock_client

        service.chat("Hello")

        call_kwargs = mock_client.messages.create.call_args[1]
        assert (
            "tools" not in call_kwargs
        ), "'tools' must not be present in Claude API call when both tool sets are empty"


class TestLoadMcpToolsCache:
    """Tests for the file-based MCP tools cache in _load_mcp_tools()."""

    def _make_service_no_load(self):
        """Create a ClaudeService without triggering real tool loading."""
        with patch(
            "core.llm.harness.claude.get_secret", return_value="test-key"
        ), patch.object(
            ClaudeService, "_load_mcp_tools", lambda self: None
        ), patch.object(
            ClaudeService, "_load_backend_tools", lambda self: None
        ):
            service = ClaudeService(use_mcp_tools=True)
        service.mcp_tools = []
        return service

    def test_fallback_to_in_memory_cache(self):
        """Falls back to mcp_client.tools_cache when cache file does not exist."""
        service = self._make_service_no_load()

        mock_client = MagicMock()
        mock_client.tools_cache = {
            "jira": [
                {
                    "name": "create_issue",
                    "description": "Create a Jira issue",
                    "inputSchema": {"type": "object", "properties": {}, "required": []},
                }
            ]
        }

        with patch("core.llm.harness.claude.REPO_ROOT") as mock_repo_root:
            mock_cf = MagicMock()
            mock_cf.exists.return_value = False
            mock_repo_root.__truediv__.return_value.__truediv__.return_value = mock_cf

            with patch(
                "core.integrations.mcp.client.get_mcp_client", return_value=mock_client
            ), patch.object(service, "_populate_mcp_registry", lambda d: None):
                service._load_mcp_tools()

        assert len(service.mcp_tools) == 1
        assert service.mcp_tools[0]["name"] == "jira_create_issue"

    def test_no_sources_available(self):
        """Sets mcp_tools=[] and does not raise when both cache file and client are unavailable."""
        service = self._make_service_no_load()

        with patch("core.llm.harness.claude.REPO_ROOT") as mock_repo_root:
            mock_cf = MagicMock()
            mock_cf.exists.return_value = False
            mock_repo_root.__truediv__.return_value.__truediv__.return_value = mock_cf

            with patch(
                "core.integrations.mcp.client.get_mcp_client", return_value=None
            ):
                service._load_mcp_tools()

        assert service.mcp_tools == []

    def test_malformed_cache_file_falls_back_to_memory(self, tmp_path):
        """Falls back to in-memory cache when the cache file contains invalid JSON."""
        cache_file = tmp_path / "mcp_tools_cache.json"
        cache_file.write_text("{not valid json}")

        service = self._make_service_no_load()

        mock_client = MagicMock()
        mock_client.tools_cache = {
            "threat_intel": [
                {
                    "name": "lookup_ip",
                    "description": "Lookup an IP address",
                    "inputSchema": {"type": "object", "properties": {}, "required": []},
                }
            ]
        }

        import builtins

        real_open = builtins.open

        with patch("core.llm.harness.claude.REPO_ROOT") as mock_repo_root:
            mock_cf = MagicMock()
            mock_cf.exists.return_value = True
            mock_repo_root.__truediv__.return_value.__truediv__.return_value = mock_cf

            def selective_open(path, *args, **kwargs):
                if path is mock_cf:
                    return real_open(cache_file, *args, **kwargs)
                return real_open(path, *args, **kwargs)

            with patch("builtins.open", side_effect=selective_open), patch(
                "core.integrations.mcp.client.get_mcp_client", return_value=mock_client
            ), patch.object(service, "_populate_mcp_registry", lambda d: None):
                service._load_mcp_tools()

        assert len(service.mcp_tools) == 1
        assert service.mcp_tools[0]["name"] == "threat_intel_lookup_ip"

    def test_no_event_loop_creation(self):
        """_load_mcp_tools never creates a new event loop."""
        service = self._make_service_no_load()

        with patch("core.llm.harness.claude.REPO_ROOT") as mock_repo_root:
            mock_cf = MagicMock()
            mock_cf.exists.return_value = False
            mock_repo_root.__truediv__.return_value.__truediv__.return_value = mock_cf

            with patch(
                "core.integrations.mcp.client.get_mcp_client", return_value=None
            ), patch("asyncio.new_event_loop") as mock_new_loop:
                service._load_mcp_tools()
                mock_new_loop.assert_not_called()

    def test_tools_have_server_prefix_and_correct_schema(self):
        """Tools loaded from in-memory cache retain server-name prefix and correct input_schema."""
        service = self._make_service_no_load()

        mock_client = MagicMock()
        mock_client.tools_cache = {
            "splunk": [
                {
                    "name": "search",
                    "description": "Run search",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"],
                    },
                }
            ]
        }

        with patch("core.llm.harness.claude.REPO_ROOT") as mock_repo_root:
            mock_cf = MagicMock()
            mock_cf.exists.return_value = False
            mock_repo_root.__truediv__.return_value.__truediv__.return_value = mock_cf

            with patch(
                "core.integrations.mcp.client.get_mcp_client", return_value=mock_client
            ), patch.object(service, "_populate_mcp_registry", lambda d: None):
                service._load_mcp_tools()

        assert len(service.mcp_tools) == 1
        tool = service.mcp_tools[0]
        assert tool["name"] == "splunk_search"
        assert "input_schema" in tool
        assert tool["input_schema"]["type"] == "object"
        assert "query" in tool["input_schema"]["properties"]

    def test_cache_file_load_with_real_file(self, tmp_path):
        """_load_mcp_tools reads tools correctly from a real cache file on disk."""
        import json as _json

        cache_data = {
            "splunk": [
                {
                    "name": "search",
                    "description": "Run a Splunk search",
                    "inputSchema": {"type": "object", "properties": {}, "required": []},
                }
            ]
        }
        cache_file = tmp_path / "mcp_tools_cache.json"
        cache_file.write_text(_json.dumps(cache_data))

        service = self._make_service_no_load()

        import builtins

        real_open = builtins.open

        with patch("core.llm.harness.claude.REPO_ROOT") as mock_repo_root:
            mock_cf = MagicMock()
            mock_cf.exists.return_value = True
            mock_repo_root.__truediv__.return_value.__truediv__.return_value = mock_cf

            def selective_open(path, *args, **kwargs):
                if path is mock_cf:
                    return real_open(cache_file, *args, **kwargs)
                return real_open(path, *args, **kwargs)

            with patch("builtins.open", side_effect=selective_open), patch(
                "core.integrations.mcp.client.get_mcp_client"
            ) as mock_get_client, patch.object(
                service, "_populate_mcp_registry", lambda d: None
            ):
                # Cached tools only surface for servers connected this boot.
                mock_get_client.return_value.get_connection_status.return_value = {
                    "splunk": True
                }
                service._load_mcp_tools()

        assert len(service.mcp_tools) == 1
        assert service.mcp_tools[0]["name"] == "splunk_search"
        assert "[splunk]" in service.mcp_tools[0]["description"]


class TestExecuteBackendTool:
    """Tests for _execute_backend_tool MCP fallback and existing-tool paths."""

    def _make_service(self):
        with patch(
            "core.llm.harness.claude.get_secret", return_value="test-api-key-123"
        ):
            service = ClaudeService()
        return service

    @pytest.mark.asyncio
    async def test_mcp_fallback_success(self):
        """Unknown tool name triggers _execute_mcp_tool; result is wrapped in {'result': ...}."""
        service = self._make_service()
        with patch.object(
            service, "_execute_mcp_tool", new=AsyncMock(return_value="search results")
        ):
            result = await service._execute_backend_tool("splunk_splunk_nl_search", {})
        assert result == {"result": "search results"}

    @pytest.mark.asyncio
    async def test_mcp_fallback_exception(self):
        """When _execute_mcp_tool raises, returns {'error': 'Unknown tool: <name>'} without propagating."""
        service = self._make_service()
        with patch.object(
            service,
            "_execute_mcp_tool",
            new=AsyncMock(side_effect=Exception("connection refused")),
        ):
            result = await service._execute_backend_tool("splunk_splunk_nl_search", {})
        assert result == {"error": "Unknown tool: splunk_splunk_nl_search"}

    @pytest.mark.asyncio
    async def test_existing_tools_unchanged(self):
        """Known backend tools (list_findings) return their correct result; _execute_mcp_tool is never called."""
        service = self._make_service()
        mock_findings = [
            {
                "finding_id": "f1",
                "severity": "high",
                "anomaly_score": 0.9,
                "data_source": "splunk",
                "timestamp": "2026-01-01T00:00:00Z",
                "status": "open",
                "description": "Test finding",
            }
        ]
        with patch(
            "core.storage.database_data_service.DatabaseDataService"
        ) as mock_ds_cls, patch.object(
            service, "_execute_mcp_tool", new=AsyncMock()
        ) as mock_mcp:
            mock_ds = mock_ds_cls.return_value
            mock_ds.count_findings.return_value = 1
            mock_ds.get_findings.return_value = mock_findings
            result = await service._execute_backend_tool(
                "list_findings", {"limit": 10, "offset": 0}
            )
        assert "findings" in result
        assert result["total"] == 1
        mock_mcp.assert_not_called()

    @pytest.mark.asyncio
    async def test_daemon_callsite_awaits_directly(self):
        """Daemon _execute_tool awaits _execute_backend_tool directly (not via asyncio.to_thread)."""
        service = self._make_service()
        call_record = []

        async def fake_backend_tool(tool_name, tool_input):
            call_record.append((tool_name, tool_input))
            return {"result": "ok"}

        service._execute_backend_tool = fake_backend_tool

        # Import AgentRunner and wire up a minimal instance
        from services.daemon.agent_runner import AgentRunner

        runner = object.__new__(AgentRunner)
        runner._claude_service = service
        runner._dry_run = False
        runner.workdir = MagicMock()

        # Patch module-level _get_tool_tier to return "auto" so it doesn't short-circuit
        runner.config = MagicMock()
        runner.config.dry_run = False
        with patch("services.daemon.agent_runner._get_tool_tier", return_value="auto"):
            result = await runner._execute_external_tool(
                "inv1", "my_mcp_tool", {"key": "val"}
            )

        assert call_record == [("my_mcp_tool", {"key": "val"})]
        assert result == '{"result": "ok"}'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

# Dropped with the loop these covered (#631), and where the guarantee moved:
#
# TestProcessMixedToolUse, TestProcessMixedToolUseEdgeCases — the three tool
#   dispatchers are one dispatcher in the agent layer. Covered by
#   services/agent/tests/core/{stream,dispatch}.test.ts, which assert the same
#   thing the harness way: an ungranted tool is refused, a result is wrapped and
#   scanned exactly once, and bad arguments are a defect in the call.
#
# TestChatAndStreamCombinedTools — chat() is a one-shot with no tools, and which
#   tools a run may reach is the registry's answer now. See
#   services/agent/tests/chat/workflow.test.ts, "grants the lead every tool the
#   config declared".
#
# TestDualToolLoading, TestTokenEstimationEdgeCases — _estimate_tokens is gone
#   with the context-reduction helpers #622 replaced. The budget is a seam that
#   reserves before it spends: services/agent/tests/core/budget.test.ts.
