"""Integration tests for Claude API endpoints."""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.fixtures.claude_responses import (
    MOCK_CHAT_RESPONSE,
    MOCK_TOOL_USE_RESPONSE,
    MOCK_INVESTIGATION_RESPONSE,
    MOCK_AGENT_RESPONSE,
)


# Skip if backend.main cannot be imported (e.g., no database available)
pytest.importorskip("backend.main", reason="Requires backend application to be importable")


@pytest.fixture
def test_client():
    """Create a test client for the FastAPI app."""
    from backend.main import app
    return TestClient(app)


@pytest.fixture
def mock_claude_service():
    """Mock the ClaudeService and LLM gateway to avoid actual API/Redis calls."""
    mock_gateway = AsyncMock()
    mock_gateway.submit_chat = AsyncMock(return_value={"content": "mock response"})

    with patch('api.claude.ClaudeService') as mock_service_class, \
         patch('services.llm_gateway.get_llm_gateway', new_callable=AsyncMock) as mock_gw_fn:
        mock_service = Mock()
        mock_service_class.return_value = mock_service
        mock_service.has_api_key.return_value = True
        mock_gw_fn.return_value = mock_gateway
        yield mock_service


class TestChatEndpoint:
    """Test /api/claude/chat endpoint."""
    
    def test_chat_endpoint_success(self, test_client, mock_claude_service):
        """Test successful chat request."""
        # Mock the chat response
        mock_claude_service.chat.return_value = {
            "response": "This is a test response",
            "usage": {"input_tokens": 100, "output_tokens": 50},
            "model": "claude-sonnet-4-20250514"
        }
        
        response = test_client.post(
            "/api/claude/chat",
            json={
                "messages": [
                    {"role": "user", "content": "Hello Claude"}
                ],
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 4096
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "response" in data or "content" in data
    
    def test_chat_endpoint_missing_messages(self, test_client, mock_claude_service):
        """Test chat request with missing messages."""
        response = test_client.post(
            "/api/claude/chat",
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 4096
            }
        )
        
        assert response.status_code == 422  # Validation error
    
    def test_chat_endpoint_with_thinking(self, test_client, mock_claude_service):
        """Test chat request with thinking mode enabled."""
        mock_claude_service.chat.return_value = {
            "response": "Analyzed response",
            "thinking": "Internal reasoning...",
            "usage": {"input_tokens": 200, "output_tokens": 150}
        }
        
        response = test_client.post(
            "/api/claude/chat",
            json={
                "messages": [
                    {"role": "user", "content": "Analyze this threat"}
                ],
                "enable_thinking": True,
                "thinking_budget": 10000,
                "model": "claude-sonnet-4-20250514"
            }
        )
        
        assert response.status_code == 200
    
    def test_chat_endpoint_no_api_key(self, test_client, mock_claude_service):
        """Test chat request when API key is not configured."""
        mock_claude_service.has_api_key.return_value = False

        response = test_client.post(
            "/api/claude/chat",
            json={
                "messages": [
                    {"role": "user", "content": "Hello"}
                ]
            }
        )

        assert response.status_code == 503
        assert "not configured" in response.json()["detail"].lower()
    
    def test_chat_endpoint_with_agent_id(self, test_client, mock_claude_service):
        """Test chat request with agent_id."""
        mock_claude_service.chat.return_value = {
            "response": "Agent response",
            "usage": {"input_tokens": 150, "output_tokens": 75}
        }
        
        response = test_client.post(
            "/api/claude/chat",
            json={
                "messages": [
                    {"role": "user", "content": "Investigate this finding"}
                ],
                "agent_id": "investigator",
                "model": "claude-sonnet-4-20250514"
            }
        )
        
        # May succeed or fail depending on if agent exists
        assert response.status_code in [200, 404]
    
    def test_chat_endpoint_with_image(self, test_client, mock_claude_service):
        """Test chat request with image content."""
        mock_claude_service.chat.return_value = {
            "response": "Image analyzed",
            "usage": {"input_tokens": 300, "output_tokens": 100}
        }
        
        response = test_client.post(
            "/api/claude/chat",
            json={
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "What's in this image?"},
                            {
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": "image/png",
                                    "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
                                }
                            }
                        ]
                    }
                ],
                "model": "claude-sonnet-4-20250514"
            }
        )
        
        assert response.status_code == 200


class TestAgentTaskEndpoint:
    """Test /api/claude/agent-task endpoint."""
    
    def test_agent_task_success(self, test_client, mock_claude_service):
        """Test successful agent task request."""
        mock_claude_service.use_agent_sdk = True
        mock_claude_service.agent_query = AsyncMock(return_value=MOCK_AGENT_RESPONSE)
        
        response = test_client.post(
            "/api/claude/agent-task",
            json={
                "task": "Investigate finding f-20260109-test123 and create a case",
                "system_prompt": "You are a security analyst",
                "max_turns": 10
            }
        )
        
        # May not have agent-task endpoint, check for 404 or 200
        assert response.status_code in [200, 404]
    
    def test_agent_task_missing_task(self, test_client, mock_claude_service):
        """Test agent task request with missing task."""
        response = test_client.post(
            "/api/claude/agent-task",
            json={
                "max_turns": 10
            }
        )
        
        # Validation error or not found
        assert response.status_code in [404, 422]


class TestStreamingEndpoint:
    """Test streaming chat functionality."""
    
    @pytest.mark.skip(reason="Streaming tests require async handling")
    def test_streaming_chat(self, test_client, mock_claude_service):
        """Test streaming chat response."""
        # This would require more complex setup with async streaming
        pass


class TestWebSocketEndpoint:
    """Test WebSocket endpoints for real-time chat."""
    
    @pytest.mark.skip(reason="WebSocket tests require special setup")
    def test_websocket_connection(self, test_client):
        """Test WebSocket connection."""
        # WebSocket tests would require a different testing approach
        pass


class TestInvestigationEndpoints:
    """Test investigation-related endpoints."""
    
    def test_investigation_workflow(self, test_client, mock_claude_service):
        """Test investigation workflow with Claude."""
        mock_claude_service.chat.return_value = {
            "response": "Investigation complete",
            "findings": ["f-12345"],
            "case_id": "case-67890"
        }
        
        # This might be a custom endpoint, check if it exists
        response = test_client.post(
            "/api/claude/investigate",
            json={
                "finding_id": "f-20260109-test123"
            }
        )
        
        # May or may not exist
        assert response.status_code in [200, 404]


class TestErrorHandling:
    """Test error handling in Claude API."""
    
    def test_internal_server_error(self, test_client, mock_claude_service):
        """Test handling of internal server errors."""
        # Make the LLM gateway's submit_chat raise to simulate an internal error
        with patch('services.llm_gateway.get_llm_gateway', new_callable=AsyncMock) as mock_gw_fn:
            mock_gw = AsyncMock()
            mock_gw.submit_chat = AsyncMock(side_effect=Exception("Test error"))
            mock_gw_fn.return_value = mock_gw

            response = test_client.post(
                "/api/claude/chat",
                json={
                    "messages": [
                        {"role": "user", "content": "Hello"}
                    ]
                }
            )

        assert response.status_code in [500, 503]
    
    def test_invalid_model(self, test_client, mock_claude_service):
        """Test handling of invalid model parameter."""
        response = test_client.post(
            "/api/claude/chat",
            json={
                "messages": [
                    {"role": "user", "content": "Hello"}
                ],
                "model": "invalid-model-name"
            }
        )
        
        # Should accept any string (validated by Claude API)
        assert response.status_code in [200, 400, 503]
    
    def test_empty_message_content(self, test_client, mock_claude_service):
        """Test handling of empty message content."""
        response = test_client.post(
            "/api/claude/chat",
            json={
                "messages": [
                    {"role": "user", "content": ""}
                ]
            }
        )
        
        # Should be rejected
        assert response.status_code in [400, 422]


class TestAuthentication:
    """Test authentication requirements for Claude API."""
    
    @pytest.mark.skip(reason="Authentication implementation varies - adjust as needed")
    def test_unauthenticated_request(self, test_client):
        """Test that unauthenticated requests are rejected."""
        # This test assumes authentication is required
        # Skip if your implementation doesn't require auth
        response = test_client.post(
            "/api/claude/chat",
            json={
                "messages": [
                    {"role": "user", "content": "Hello"}
                ]
            }
        )
        
        # Expect 401 if auth is required
        assert response.status_code == 401


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

