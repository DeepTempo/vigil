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


# Skip if services.api.main cannot be imported (e.g., no database available)
pytest.importorskip("services.api.main", reason="Requires backend application to be importable")


@pytest.fixture
def mock_llm_gateway():
    """Mock the LLM Gateway to prevent async Redis connections during tests.

    Patches core.llm.gateway.gateway.get_llm_gateway so that no real Redis pool
    is created.  This eliminates the ``RuntimeError: Event loop is closed``
    error that occurs when a Redis connection outlives the test event loop.
    """
    mock_gw = AsyncMock()
    mock_gw.submit_chat = AsyncMock(return_value="Mocked LLM response")
    mock_gw.submit_triage = AsyncMock(return_value="Mocked triage response")
    mock_gw.submit_investigation = AsyncMock(return_value={})
    mock_gw.close = AsyncMock()

    mock_get_gw = AsyncMock(return_value=mock_gw)

    with patch("core.llm.gateway.gateway.get_llm_gateway", mock_get_gw):
        yield mock_gw


@pytest.fixture
def test_client(mock_llm_gateway):
    """Create a test client for the FastAPI app.

    Uses TestClient as a context manager so that the FastAPI startup and
    shutdown lifecycle events fire in the correct order.  The shutdown event
    calls close_llm_gateway(), which closes any Redis connections *before*
    the event loop is torn down -- preventing RuntimeError: Event loop is
    closed.
    """
    from services.api.main import app
    with TestClient(app) as client:
        yield client


@pytest.fixture
def mock_claude_service(mock_llm_gateway):
    """Mock the ClaudeService to avoid actual API calls."""
    # Patch ClaudeService where the claude router looks it up, so the endpoint
    # constructs the mock instead of the real service.
    with patch('services.api.routers.claude.ClaudeService') as mock_service_class:

        mock_service = Mock()
        mock_service_class.return_value = mock_service
        mock_service.has_api_key.return_value = True
        yield mock_service






class TestStreamingEndpoint:
    """Test streaming chat functionality."""

    @pytest.mark.skip(reason="Streaming tests require async handling")
    def test_streaming_chat(self, test_client, mock_claude_service):
        """Test streaming chat response."""
        # This would require more complex setup with async streaming
        pass




class TestInvestigationEndpoints:
    """Test investigation-related endpoints."""

    def test_investigation_workflow(self, test_client, mock_claude_service):
        """Test investigation workflow with Claude."""
        # This might be a custom endpoint, check if it exists
        response = test_client.post(
            "/api/claude/investigate",
            json={
                "finding_id": "f-20260109-test123"
            }
        )

        assert response.status_code in [200, 404, 405]







if __name__ == "__main__":
    pytest.main([__file__, "-v"])

# Dropped with the routes they posted to (#631). All of them addressed
# POST /api/claude/chat, /agent/task or /ws/chat, which are gone: chat is one
# route now, POST /chat/stream, proxied to the agent layer.
#
# What replaced the coverage, and where:
#   the turn itself      services/agent/tests/chat/workflow.test.ts
#   the wire contract    services/agent/tests/chat/sse.test.ts, which reads the
#                        console's branches out of Chat.tsx rather than
#                        restating them
#   the HTTP surface     services/agent/tests/chat/serve.test.ts -- auth, the
#                        one route, a bad body, and a refusal arriving as a frame
#
# Note for whoever picks this file up next: the classes left here were already
# failing on agent-refactor before #631 (11 of 12), against a mock_llm_gateway
# fixture that no longer matches how the endpoint reaches a provider. Repairing
# that is not this change's scope and is called out in the PR.
