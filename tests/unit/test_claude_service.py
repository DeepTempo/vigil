"""Unit tests for Claude service."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from services.claude_service import ClaudeService
from tests.fixtures.claude_responses import (
    MOCK_CHAT_RESPONSE,
    MOCK_TOOL_USE_RESPONSE,
    MOCK_THINKING_RESPONSE,
    MOCK_RATE_LIMIT_ERROR,
    MOCK_INVALID_REQUEST_ERROR,
    MOCK_AUTH_ERROR,
    MOCK_CONVERSATION_HISTORY,
)


class TestClaudeServiceInitialization:
    """Test ClaudeService initialization."""
    
    @patch('services.claude_service.get_secret')
    def test_init_default_config(self, mock_get_secret):
        """Test initialization with default configuration."""
        mock_get_secret.return_value = "test-api-key-123"
        
        service = ClaudeService()
        
        assert service.use_mcp_tools is True
        assert service.enable_thinking is False
        assert service.thinking_budget == 10000
        assert service.sessions == {}
        assert service.default_system_prompt is not None
    
    @patch('services.claude_service.get_secret')
    def test_init_custom_config(self, mock_get_secret):
        """Test initialization with custom configuration."""
        mock_get_secret.return_value = "test-api-key-123"
        
        service = ClaudeService(
            use_mcp_tools=False,
            enable_thinking=True,
            thinking_budget=20000,
            use_agent_sdk=False
        )
        
        assert service.use_mcp_tools is False
        assert service.enable_thinking is True
        assert service.thinking_budget == 20000
        assert service.use_agent_sdk is False
    
    @patch('services.claude_service.get_secret')
    def test_init_no_api_key(self, mock_get_secret):
        """Test initialization when API key is not available."""
        mock_get_secret.return_value = None
        
        service = ClaudeService()
        
        assert service.api_key is None
        assert service.client is None
        assert service.async_client is None


class TestClaudeServicePrompts:
    """Test prompt building and management."""
    
    @patch('services.claude_service.get_secret')
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
    
    @patch('services.claude_service.get_secret')
    def test_system_prompt_includes_mcp_tools_section(self, mock_get_secret):
        """Test that system prompt includes MCP tools documentation."""
        mock_get_secret.return_value = "test-api-key-123"
        
        service = ClaudeService(use_mcp_tools=True)
        prompt = service._get_default_system_prompt()
        
        assert "available_mcp_tools" in prompt
        assert "deeptempo-findings" in prompt


class TestClaudeServiceSessionManagement:
    """Test session management for multi-turn conversations."""
    
    @patch('services.claude_service.get_secret')
    def test_create_session(self, mock_get_secret):
        """Test creating a new session."""
        mock_get_secret.return_value = "test-api-key-123"
        
        service = ClaudeService()
        session_id = "test-session-123"
        
        # Add messages to session
        service.sessions[session_id] = MOCK_CONVERSATION_HISTORY.copy()
        
        assert session_id in service.sessions
        assert len(service.sessions[session_id]) == 4
    
    @patch('services.claude_service.get_secret')
    def test_clear_session(self, mock_get_secret):
        """Test clearing a session."""
        mock_get_secret.return_value = "test-api-key-123"
        
        service = ClaudeService()
        session_id = "test-session-123"
        
        # Add messages to session
        service.sessions[session_id] = MOCK_CONVERSATION_HISTORY.copy()
        
        # Clear session
        if session_id in service.sessions:
            del service.sessions[session_id]
        
        assert session_id not in service.sessions
    
    @patch('services.claude_service.get_secret')
    def test_session_isolation(self, mock_get_secret):
        """Test that sessions are isolated from each other."""
        mock_get_secret.return_value = "test-api-key-123"
        
        service = ClaudeService()
        
        session1_id = "session-1"
        session2_id = "session-2"
        
        service.sessions[session1_id] = [{"role": "user", "content": "Message 1"}]
        service.sessions[session2_id] = [{"role": "user", "content": "Message 2"}]
        
        assert len(service.sessions[session1_id]) == 1
        assert len(service.sessions[session2_id]) == 1
        assert service.sessions[session1_id] != service.sessions[session2_id]


class TestClaudeServiceAPIInteraction:
    """Test API interaction (mocked)."""
    
    @patch('services.claude_service.get_secret')
    @patch('services.claude_service.Anthropic')
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
                "output_tokens": mock_response.usage.output_tokens
            }
        }
        
        assert result["response"] == "Test response"
        assert result["usage"]["input_tokens"] == 100
        assert result["usage"]["output_tokens"] == 50
    
    @patch('services.claude_service.get_secret')
    @patch('services.claude_service.Anthropic')
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
    
    @patch('services.claude_service.get_secret')
    def test_missing_api_key_error(self, mock_get_secret):
        """Test behavior when API key is missing."""
        mock_get_secret.return_value = None
        
        service = ClaudeService()
        
        assert service.api_key is None
        assert service.client is None
    
    @patch('services.claude_service.get_secret')
    @patch('services.claude_service.Anthropic')
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
            body=MOCK_RATE_LIMIT_ERROR
        )
        
        service = ClaudeService()
        service.client = mock_client
        
        # Test that rate limit error is raised
        with pytest.raises(RateLimitError):
            mock_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1000,
                messages=[{"role": "user", "content": "test"}]
            )
    
    @patch('services.claude_service.get_secret')
    @patch('services.claude_service.Anthropic')
    def test_authentication_error_handling(self, mock_anthropic, mock_get_secret):
        """Test authentication error handling."""
        mock_get_secret.return_value = "invalid-api-key"
        
        mock_client = Mock()
        mock_anthropic.return_value = mock_client
        
        # Simulate authentication error
        from anthropic import AuthenticationError
        mock_client.messages.create.side_effect = AuthenticationError(
            "Invalid API key",
            response=Mock(status_code=401),
            body=MOCK_AUTH_ERROR
        )
        
        service = ClaudeService()
        service.client = mock_client
        
        # Test that auth error is raised
        with pytest.raises(AuthenticationError):
            mock_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1000,
                messages=[{"role": "user", "content": "test"}]
            )


class TestClaudeServiceThinkingMode:
    """Test extended thinking mode configuration."""
    
    @patch('services.claude_service.get_secret')
    def test_thinking_mode_enabled(self, mock_get_secret):
        """Test that thinking mode can be enabled."""
        mock_get_secret.return_value = "test-api-key-123"
        
        service = ClaudeService(enable_thinking=True, thinking_budget=15000)
        
        assert service.enable_thinking is True
        assert service.thinking_budget == 15000
    
    @patch('services.claude_service.get_secret')
    def test_thinking_mode_disabled_by_default(self, mock_get_secret):
        """Test that thinking mode is disabled by default."""
        mock_get_secret.return_value = "test-api-key-123"
        
        service = ClaudeService()
        
        assert service.enable_thinking is False


class TestClaudeServiceMCPTools:
    """Test MCP tool integration."""

    @patch('services.claude_service.get_secret')
    def test_mcp_tools_enabled(self, mock_get_secret):
        """Test that MCP tools can be enabled."""
        mock_get_secret.return_value = "test-api-key-123"

        service = ClaudeService(use_mcp_tools=True)

        assert service.use_mcp_tools is True

    @patch('services.claude_service.get_secret')
    def test_mcp_tools_disabled(self, mock_get_secret):
        """Test that MCP tools can be disabled."""
        mock_get_secret.return_value = "test-api-key-123"

        service = ClaudeService(use_mcp_tools=False)

        assert service.use_mcp_tools is False
        assert service.mcp_tools == []


class TestDualToolLoading:
    """Test that backend tools and MCP tools load independently and simultaneously."""

    @patch('services.claude_service.get_secret')
    @patch('services.claude_service.BACKEND_TOOLS_AVAILABLE', True)
    @patch('services.claude_service.BACKEND_TOOLS', [
        {'name': 'backend_tool_1', 'description': 'Backend tool', 'input_schema': {'type': 'object', 'properties': {}}},
    ])
    def test_both_tool_sets_load_when_both_flags_enabled(self, mock_get_secret):
        """Both backend_tools and mcp_tools are populated when both flags are True."""
        mock_get_secret.return_value = "test-api-key-123"

        fake_mcp_tools = [
            {'name': 'mcp_tool_1', 'description': 'MCP tool', 'input_schema': {'type': 'object', 'properties': {}}},
        ]

        with patch.object(ClaudeService, '_load_mcp_tools', lambda self: setattr(self, 'mcp_tools', fake_mcp_tools)):
            service = ClaudeService(use_backend_tools=True, use_mcp_tools=True)

        assert len(service.backend_tools) > 0, "backend_tools should be non-empty"
        assert len(service.mcp_tools) > 0, "mcp_tools should be non-empty"

    @patch('services.claude_service.get_secret')
    @patch('services.claude_service.BACKEND_TOOLS_AVAILABLE', True)
    @patch('services.claude_service.BACKEND_TOOLS', [
        {'name': 'backend_tool_1', 'description': 'Backend tool', 'input_schema': {'type': 'object', 'properties': {}}},
        {'name': 'backend_tool_2', 'description': 'Backend tool 2', 'input_schema': {'type': 'object', 'properties': {}}},
    ])
    def test_token_estimation_sums_both_tool_sets(self, mock_get_secret):
        """Token estimation equals the sum of each tool set individually when both are loaded."""
        import json
        mock_get_secret.return_value = "test-api-key-123"

        fake_mcp_tools = [
            {'name': 'mcp_tool_1', 'description': 'MCP tool', 'input_schema': {'type': 'object', 'properties': {}}},
        ]

        with patch.object(ClaudeService, '_load_mcp_tools', lambda self: setattr(self, 'mcp_tools', fake_mcp_tools)):
            service = ClaudeService(use_backend_tools=True, use_mcp_tools=True)

        # Compute expected token sum individually
        backend_tokens = service._estimate_tokens(json.dumps(service.backend_tools))
        mcp_tokens = service._estimate_tokens(json.dumps(service.mcp_tools))
        expected_total = backend_tokens + mcp_tokens

        # _needs_context_reduction returns (needs_reduction, total_tokens, available_tokens)
        # available_tokens = max_context - system_tokens - tool_tokens
        # With no messages and no system prompt: available = max_context - tool_tokens
        max_context = 180000
        _, _, available = service._needs_context_reduction([], system_prompt=None, max_context_tokens=max_context)

        actual_tool_tokens = max_context - available
        assert actual_tool_tokens == expected_total, (
            f"Expected tool tokens {expected_total}, got {actual_tool_tokens}"
        )

    @patch('services.claude_service.get_secret')
    @patch('services.claude_service.BACKEND_TOOLS_AVAILABLE', True)
    @patch('services.claude_service.BACKEND_TOOLS', [
        {'name': 'backend_tool_1', 'description': 'Backend tool', 'input_schema': {'type': 'object', 'properties': {}}},
    ])
    def test_only_backend_tools_when_mcp_disabled(self, mock_get_secret):
        """When only use_backend_tools=True, mcp_tools stays empty."""
        mock_get_secret.return_value = "test-api-key-123"

        service = ClaudeService(use_backend_tools=True, use_mcp_tools=False)

        assert len(service.backend_tools) > 0
        assert service.mcp_tools == []

    @patch('services.claude_service.get_secret')
    def test_only_mcp_tools_when_backend_disabled(self, mock_get_secret):
        """When only use_mcp_tools=True, backend_tools stays empty."""
        mock_get_secret.return_value = "test-api-key-123"

        fake_mcp_tools = [
            {'name': 'mcp_tool_1', 'description': 'MCP tool', 'input_schema': {'type': 'object', 'properties': {}}},
        ]

        with patch.object(ClaudeService, '_load_mcp_tools', lambda self: setattr(self, 'mcp_tools', fake_mcp_tools)):
            service = ClaudeService(use_backend_tools=False, use_mcp_tools=True)

        assert service.backend_tools == []
        assert len(service.mcp_tools) > 0


class TestProcessMixedToolUse:
    """Tests for _process_mixed_tool_use() routing method."""

    def _make_service(self, backend_tools, mcp_tools):
        """Create a ClaudeService with pre-populated tool lists (no real init)."""
        with patch('services.claude_service.get_secret', return_value="test-key"), \
             patch.object(ClaudeService, '_load_backend_tools', lambda self: None), \
             patch.object(ClaudeService, '_load_mcp_tools', lambda self: None):
            service = ClaudeService(use_backend_tools=False, use_mcp_tools=False)
        service.backend_tools = backend_tools
        service.mcp_tools = mcp_tools
        return service

    def _make_tool_use_item(self, name, tool_id="toolu_1", input_data=None):
        """Create a mock tool-use block (object format, as Claude API returns)."""
        item = Mock()
        item.type = "tool_use"
        item.name = name
        item.id = tool_id
        item.input = input_data or {}
        return item

    @pytest.mark.asyncio
    async def test_mixed_content_dispatches_correctly(self):
        """Backend-named tool goes to _process_backend_tool_use; others go to _process_tool_use."""
        backend_tools = [{'name': 'backend_op', 'description': 'b', 'input_schema': {}}]
        mcp_tools = [{'name': 'mcp_op', 'description': 'm', 'input_schema': {}}]
        service = self._make_service(backend_tools, mcp_tools)

        backend_item = self._make_tool_use_item('backend_op', tool_id='toolu_b')
        mcp_item = self._make_tool_use_item('mcp_op', tool_id='toolu_m')
        content = [backend_item, mcp_item]

        backend_result = [{'type': 'tool_result', 'tool_use_id': 'toolu_b', 'content': [{'type': 'text', 'text': 'backend'}]}]
        mcp_result = [{'type': 'tool_result', 'tool_use_id': 'toolu_m', 'content': [{'type': 'text', 'text': 'mcp'}]}]

        with patch.object(service, '_process_backend_tool_use', return_value=backend_result) as mock_backend, \
             patch.object(service, '_process_tool_use', return_value=mcp_result) as mock_mcp:
            results = await service._process_mixed_tool_use(content)

        # Each processor called with the single matching item wrapped in a list
        mock_backend.assert_called_once_with([backend_item])
        mock_mcp.assert_called_once_with([mcp_item])
        # Both results combined
        assert len(results) == 2
        assert results[0] == backend_result[0]
        assert results[1] == mcp_result[0]

    @pytest.mark.asyncio
    async def test_backend_only_content_dispatches_to_backend_processor(self):
        """All items with backend names go exclusively to _process_backend_tool_use."""
        backend_tools = [
            {'name': 'tool_a', 'description': 'a', 'input_schema': {}},
            {'name': 'tool_b', 'description': 'b', 'input_schema': {}},
        ]
        service = self._make_service(backend_tools, mcp_tools=[])

        item_a = self._make_tool_use_item('tool_a', tool_id='toolu_a')
        item_b = self._make_tool_use_item('tool_b', tool_id='toolu_b')
        content = [item_a, item_b]

        result_a = [{'type': 'tool_result', 'tool_use_id': 'toolu_a', 'content': [{'type': 'text', 'text': 'r_a'}]}]
        result_b = [{'type': 'tool_result', 'tool_use_id': 'toolu_b', 'content': [{'type': 'text', 'text': 'r_b'}]}]

        side_effects = [result_a, result_b]
        with patch.object(service, '_process_backend_tool_use', side_effect=side_effects) as mock_backend, \
             patch.object(service, '_process_tool_use') as mock_mcp:
            results = await service._process_mixed_tool_use(content)

        assert mock_backend.call_count == 2
        mock_mcp.assert_not_called()
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_mcp_only_content_dispatches_to_mcp_processor(self):
        """All items with non-backend names go exclusively to _process_tool_use."""
        service = self._make_service(backend_tools=[], mcp_tools=[
            {'name': 'ext_search', 'description': 'search', 'input_schema': {}},
        ])

        item = self._make_tool_use_item('ext_search', tool_id='toolu_s')
        content = [item]

        mcp_result = [{'type': 'tool_result', 'tool_use_id': 'toolu_s', 'content': [{'type': 'text', 'text': 'found'}]}]

        with patch.object(service, '_process_backend_tool_use') as mock_backend, \
             patch.object(service, '_process_tool_use', return_value=mcp_result) as mock_mcp:
            results = await service._process_mixed_tool_use(content)

        mock_backend.assert_not_called()
        mock_mcp.assert_called_once_with([item])
        assert results == mcp_result

    @pytest.mark.asyncio
    async def test_empty_content_returns_empty_list(self):
        """Empty content list returns empty results without calling any processor."""
        service = self._make_service(backend_tools=[], mcp_tools=[])

        with patch.object(service, '_process_backend_tool_use') as mock_backend, \
             patch.object(service, '_process_tool_use') as mock_mcp:
            results = await service._process_mixed_tool_use([])

        mock_backend.assert_not_called()
        mock_mcp.assert_not_called()
        assert results == []

    @pytest.mark.asyncio
    async def test_dict_format_items_are_handled(self):
        """Items in dict format (not object) are routed correctly."""
        backend_tools = [{'name': 'dict_tool', 'description': 'd', 'input_schema': {}}]
        service = self._make_service(backend_tools, mcp_tools=[])

        # Dict-format item (as opposed to Mock object)
        dict_item = {'type': 'tool_use', 'id': 'toolu_d', 'name': 'dict_tool', 'input': {}}
        content = [dict_item]

        backend_result = [{'type': 'tool_result', 'tool_use_id': 'toolu_d', 'content': [{'type': 'text', 'text': 'ok'}]}]

        with patch.object(service, '_process_backend_tool_use', return_value=backend_result) as mock_backend, \
             patch.object(service, '_process_tool_use') as mock_mcp:
            results = await service._process_mixed_tool_use(content)

        mock_backend.assert_called_once_with([dict_item])
        mock_mcp.assert_not_called()
        assert results == backend_result


class TestChatAndStreamCombinedTools:
    """Tests verifying chat() and stream() pass combined tool lists to the Claude API."""

    BACKEND_TOOL = {'name': 'backend_op', 'description': 'Backend', 'input_schema': {'type': 'object', 'properties': {}}}
    MCP_TOOL = {'name': 'mcp_op', 'description': 'MCP', 'input_schema': {'type': 'object', 'properties': {}}}

    def _make_service_with_both_tools(self):
        with patch('services.claude_service.get_secret', return_value="test-key"), \
             patch.object(ClaudeService, '_load_backend_tools', lambda self: None), \
             patch.object(ClaudeService, '_load_mcp_tools', lambda self: None):
            service = ClaudeService(use_backend_tools=True, use_mcp_tools=True)
        service.backend_tools = [self.BACKEND_TOOL]
        service.mcp_tools = [self.MCP_TOOL]
        return service

    @patch('services.claude_service.Anthropic')
    def test_chat_passes_combined_tools_to_api(self, mock_anthropic):
        """chat() passes both backend and MCP tools combined to the Claude API."""
        mock_client = Mock()
        mock_anthropic.return_value = mock_client

        mock_response = Mock()
        mock_response.content = [Mock(type="text", text="Done")]
        mock_response.stop_reason = "end_turn"
        mock_response.model = "claude-sonnet-4-5-20250929"
        mock_response.usage = Mock(input_tokens=50, output_tokens=10)
        mock_client.messages.create.return_value = mock_response

        service = self._make_service_with_both_tools()
        service.client = mock_client

        service.chat("Hello")

        call_kwargs = mock_client.messages.create.call_args[1]
        tools_passed = call_kwargs.get('tools', [])
        tool_names = [t['name'] for t in tools_passed]
        assert 'backend_op' in tool_names, "backend tool should be in combined list"
        assert 'mcp_op' in tool_names, "MCP tool should be in combined list"
        assert len(tools_passed) == 2

    @pytest.mark.asyncio
    @patch('services.claude_service.AsyncAnthropic')
    async def test_stream_passes_combined_tools_to_api(self, mock_async_anthropic):
        """chat_stream() passes both backend and MCP tools combined to the Claude API."""
        from unittest.mock import AsyncMock

        # Build an async context manager mock for messages.stream(...)
        captured_kwargs = {}

        mock_final_message = Mock()
        mock_final_message.content = [Mock(type="text", text="Done")]
        mock_final_message.stop_reason = "end_turn"

        async def _empty_aiter():
            return
            yield  # make it an async generator

        mock_stream_cm = MagicMock()
        mock_stream_cm.__aenter__ = AsyncMock(return_value=mock_stream_cm)
        mock_stream_cm.__aexit__ = AsyncMock(return_value=False)
        mock_stream_cm.__aiter__ = Mock(return_value=_empty_aiter())  # proper async iterator
        mock_stream_cm.get_final_message = AsyncMock(return_value=mock_final_message)

        mock_async_client = Mock()
        mock_async_anthropic.return_value = mock_async_client

        def capture_stream(**kwargs):
            captured_kwargs.update(kwargs)
            return mock_stream_cm

        mock_async_client.messages.stream = capture_stream

        service = self._make_service_with_both_tools()
        service.async_client = mock_async_client

        # Consume the async generator to drive execution
        chunks = []
        async for chunk in service.chat_stream("Hello"):
            chunks.append(chunk)

        tools_passed = captured_kwargs.get('tools', [])
        tool_names = [t['name'] for t in tools_passed]
        assert 'backend_op' in tool_names, "backend tool should be in combined stream list"
        assert 'mcp_op' in tool_names, "MCP tool should be in combined stream list"
        assert len(tools_passed) == 2


class TestTokenEstimationEdgeCases:
    """Edge case tests for tool-token estimation with partial or empty tool sets."""

    def _make_service(self, backend_tools, mcp_tools, backend_enabled=True, mcp_enabled=True):
        """Return a ClaudeService with pre-set tool lists (no external calls)."""
        with patch('services.claude_service.get_secret', return_value="test-key"), \
             patch.object(ClaudeService, '_load_backend_tools', lambda self: None), \
             patch.object(ClaudeService, '_load_mcp_tools', lambda self: None):
            service = ClaudeService(
                use_backend_tools=backend_enabled,
                use_mcp_tools=mcp_enabled,
            )
        service.backend_tools = backend_tools
        service.mcp_tools = mcp_tools
        return service

    def _tool_tokens(self, service, max_context=180000):
        """Compute the tool-token contribution via _needs_context_reduction."""
        _, _, available = service._needs_context_reduction(
            [], system_prompt=None, max_context_tokens=max_context
        )
        return max_context - available

    def test_token_estimation_empty_backend_only_counts_mcp(self):
        """When backend_tools is empty but mcp_tools has items, only MCP tokens counted."""
        import json
        mcp_tools = [
            {'name': 'mcp_t', 'description': 'MCP tool', 'input_schema': {'type': 'object'}},
        ]
        service = self._make_service(backend_tools=[], mcp_tools=mcp_tools)

        expected_mcp = service._estimate_tokens(json.dumps(mcp_tools))
        assert self._tool_tokens(service) == expected_mcp, (
            "Only MCP token cost should be counted when backend_tools is empty"
        )

    def test_token_estimation_empty_mcp_only_counts_backend(self):
        """When mcp_tools is empty but backend_tools has items, only backend tokens counted."""
        import json
        backend_tools = [
            {'name': 'backend_t', 'description': 'Backend tool', 'input_schema': {'type': 'object'}},
        ]
        service = self._make_service(backend_tools=backend_tools, mcp_tools=[])

        expected_backend = service._estimate_tokens(json.dumps(backend_tools))
        assert self._tool_tokens(service) == expected_backend, (
            "Only backend token cost should be counted when mcp_tools is empty"
        )

    def test_token_estimation_both_empty_contributes_zero(self):
        """When both tool sets are empty lists, no tool tokens are counted."""
        service = self._make_service(backend_tools=[], mcp_tools=[])
        assert self._tool_tokens(service) == 0, (
            "tool_tokens should be 0 when both backend_tools and mcp_tools are empty"
        )


class TestEmptyToolSetsPassNoneToApi:
    """Verify that empty tool lists result in tools=None (not []) when calling the API."""

    BACKEND_TOOL = {'name': 'bt', 'description': 'B', 'input_schema': {'type': 'object', 'properties': {}}}
    MCP_TOOL = {'name': 'mt', 'description': 'M', 'input_schema': {'type': 'object', 'properties': {}}}

    def _make_service(self, backend_tools, mcp_tools):
        with patch('services.claude_service.get_secret', return_value="test-key"), \
             patch.object(ClaudeService, '_load_backend_tools', lambda self: None), \
             patch.object(ClaudeService, '_load_mcp_tools', lambda self: None):
            service = ClaudeService(use_backend_tools=True, use_mcp_tools=True)
        service.backend_tools = backend_tools
        service.mcp_tools = mcp_tools
        return service

    @patch('services.claude_service.Anthropic')
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
        assert 'tools' not in call_kwargs, (
            "'tools' must not be present in Claude API call when both tool sets are empty"
        )


class TestProcessMixedToolUseEdgeCases:
    """Edge-case tests for _process_mixed_tool_use routing."""

    def _make_service(self, backend_tools, mcp_tools):
        with patch('services.claude_service.get_secret', return_value="test-key"), \
             patch.object(ClaudeService, '_load_backend_tools', lambda self: None), \
             patch.object(ClaudeService, '_load_mcp_tools', lambda self: None):
            service = ClaudeService(use_backend_tools=False, use_mcp_tools=False)
        service.backend_tools = backend_tools
        service.mcp_tools = mcp_tools
        return service

    def _make_tool_use_item(self, name, tool_id="toolu_1"):
        item = Mock()
        item.type = "tool_use"
        item.name = name
        item.id = tool_id
        item.input = {}
        return item

    @pytest.mark.asyncio
    async def test_tool_name_collision_backend_takes_precedence(self):
        """When both backend and MCP tools share a name, the backend processor is called."""
        shared_name = 'shared_tool'
        backend_tools = [{'name': shared_name, 'description': 'backend version', 'input_schema': {}}]
        mcp_tools = [{'name': shared_name, 'description': 'mcp version', 'input_schema': {}}]
        service = self._make_service(backend_tools, mcp_tools)

        item = self._make_tool_use_item(shared_name, tool_id='toolu_shared')
        backend_result = [{'type': 'tool_result', 'tool_use_id': 'toolu_shared',
                           'content': [{'type': 'text', 'text': 'from_backend'}]}]

        with patch.object(service, '_process_backend_tool_use', return_value=backend_result) as mock_backend, \
             patch.object(service, '_process_tool_use') as mock_mcp:
            results = await service._process_mixed_tool_use([item])

        # backend_tool_names set is checked first → backend wins
        mock_backend.assert_called_once_with([item])
        mock_mcp.assert_not_called()
        assert results == backend_result

    @pytest.mark.asyncio
    async def test_backend_processor_receives_single_element_list(self):
        """Each backend tool-use item is wrapped in a one-element list before dispatch."""
        backend_tools = [{'name': 'tool_x', 'description': 'x', 'input_schema': {}}]
        service = self._make_service(backend_tools, mcp_tools=[])

        item_x = self._make_tool_use_item('tool_x', tool_id='toolu_x')
        result_x = [{'type': 'tool_result', 'tool_use_id': 'toolu_x',
                     'content': [{'type': 'text', 'text': 'ok'}]}]

        with patch.object(service, '_process_backend_tool_use', return_value=result_x) as mock_backend:
            await service._process_mixed_tool_use([item_x])

        # Verify the processor received exactly a single-element list
        mock_backend.assert_called_once_with([item_x])
        arg = mock_backend.call_args[0][0]
        assert isinstance(arg, list) and len(arg) == 1, (
            "_process_backend_tool_use must receive a [single_item] list, not the raw item"
        )

    @pytest.mark.asyncio
    async def test_mcp_processor_receives_single_element_list(self):
        """Each MCP tool-use item is wrapped in a one-element list before dispatch."""
        service = self._make_service(backend_tools=[], mcp_tools=[
            {'name': 'remote_scan', 'description': 'scan', 'input_schema': {}}
        ])

        item = self._make_tool_use_item('remote_scan', tool_id='toolu_scan')
        mcp_result = [{'type': 'tool_result', 'tool_use_id': 'toolu_scan',
                       'content': [{'type': 'text', 'text': 'scanned'}]}]

        with patch.object(service, '_process_tool_use', return_value=mcp_result) as mock_mcp:
            await service._process_mixed_tool_use([item])

        mock_mcp.assert_called_once_with([item])
        arg = mock_mcp.call_args[0][0]
        assert isinstance(arg, list) and len(arg) == 1, (
            "_process_tool_use must receive a [single_item] list, not the raw item"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

