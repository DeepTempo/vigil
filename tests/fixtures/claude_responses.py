"""Mock Claude API responses for testing."""

from datetime import datetime


# Standard chat response
MOCK_CHAT_RESPONSE = {
    "id": "msg_01AbCdEfGhIjKlMnOpQr",
    "type": "message",
    "role": "assistant",
    "content": [{
        "type": "text",
        "text": "This is a test response from Claude. I can help you analyze security findings and investigate threats."
    }],
    "model": "claude-sonnet-4-20250514",
    "stop_reason": "end_turn",
    "usage": {
        "input_tokens": 125,
        "output_tokens": 50
    }
}

# Response with tool use
MOCK_TOOL_USE_RESPONSE = {
    "id": "msg_01ToolUseExample123",
    "type": "message",
    "role": "assistant",
    "content": [
        {
            "type": "text",
            "text": "Let me retrieve that finding for you."
        },
        {
            "type": "tool_use",
            "id": "toolu_01FindingRetrieval",
            "name": "deeptempo-findings_get_finding",
            "input": {
                "finding_id": "f-20260109-test123"
            }
        }
    ],
    "model": "claude-sonnet-4-20250514",
    "stop_reason": "tool_use",
    "usage": {
        "input_tokens": 200,
        "output_tokens": 125
    }
}

# Response with extended thinking
MOCK_THINKING_RESPONSE = {
    "id": "msg_01ThinkingExample456",
    "type": "message",
    "role": "assistant",
    "content": [
        {
            "type": "thinking",
            "thinking": "Let me analyze this security finding carefully. I need to consider the severity, MITRE techniques, and potential impact..."
        },
        {
            "type": "text",
            "text": "Based on my analysis, this appears to be a high-severity threat involving lateral movement."
        }
    ],
    "model": "claude-sonnet-4-20250514",
    "stop_reason": "end_turn",
    "usage": {
        "input_tokens": 300,
        "output_tokens": 200
    }
}

# Error response - rate limit
MOCK_RATE_LIMIT_ERROR = {
    "type": "error",
    "error": {
        "type": "rate_limit_error",
        "message": "Rate limit exceeded. Please try again later."
    }
}

# Error response - invalid request
MOCK_INVALID_REQUEST_ERROR = {
    "type": "error",
    "error": {
        "type": "invalid_request_error",
        "message": "Invalid request: missing required field 'messages'"
    }
}

# Error response - authentication
MOCK_AUTH_ERROR = {
    "type": "error",
    "error": {
        "type": "authentication_error",
        "message": "Invalid API key provided"
    }
}

# Investigation workflow response
MOCK_INVESTIGATION_RESPONSE = {
    "id": "msg_01Investigation789",
    "type": "message",
    "role": "assistant",
    "content": [{
        "type": "text",
        "text": """# Investigation Summary

**Finding**: Suspicious network traffic detected
**Severity**: High
**MITRE Techniques**: T1071.001, T1573.001

## Key Indicators:
- Source IP: 10.0.1.5
- Destination IP: 185.220.101.5 (known C2 server)
- Port: 443 (HTTPS)

## Recommended Actions:
1. Isolate affected host immediately
2. Capture network traffic for analysis
3. Check for other compromised hosts
4. Review firewall logs for similar connections"""
    }],
    "model": "claude-sonnet-4-20250514",
    "stop_reason": "end_turn",
    "usage": {
        "input_tokens": 500,
        "output_tokens": 250
    }
}

# Agent SDK response
MOCK_AGENT_RESPONSE = {
    "success": True,
    "result": {
        "messages": [
            {
                "role": "assistant",
                "content": "I've analyzed the finding and created a case for investigation."
            }
        ],
        "tool_calls": [
            {
                "tool": "deeptempo-findings_get_finding",
                "input": {"finding_id": "f-20260109-test123"},
                "output": {"title": "Suspicious network traffic", "severity": "high"}
            },
            {
                "tool": "deeptempo-findings_create_case",
                "input": {"title": "Investigate suspicious traffic", "findings": ["f-20260109-test123"]},
                "output": {"case_id": "case-20260128-auto123"}
            }
        ]
    }
}

# Streaming response chunks
MOCK_STREAMING_CHUNKS = [
    {
        "type": "message_start",
        "message": {
            "id": "msg_01Stream123",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-20250514",
            "usage": {"input_tokens": 100, "output_tokens": 0}
        }
    },
    {
        "type": "content_block_start",
        "index": 0,
        "content_block": {"type": "text", "text": ""}
    },
    {
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": "Let"}
    },
    {
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": " me"}
    },
    {
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": " help"}
    },
    {
        "type": "content_block_stop",
        "index": 0
    },
    {
        "type": "message_delta",
        "delta": {"stop_reason": "end_turn"},
        "usage": {"output_tokens": 50}
    },
    {
        "type": "message_stop"
    }
]

