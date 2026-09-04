"""Registry tracks enable intent, not the last call_tool's is_connected bit (#809)."""

from __future__ import annotations

import pytest

from core.integrations.mcp.registry import (
    MCPRegistry,
    deactivate,
    live_mcp_tools,
    register_connected,
)

pytestmark = pytest.mark.unit

TOOL = {
    "name": "splunk_execute",
    "description": "x",
    "inputSchema": {},
}
FLAT = "splunk-selfhosted_splunk_execute"


class _Client:
    mcp_service = None
    tools_cache = {"splunk-selfhosted": [TOOL]}

    def __init__(self, connected: bool):
        self._connected = connected

    def get_connection_status(self):
        return {"splunk-selfhosted": self._connected}


def test_dropped_session_still_appears_in_live_mcp_tools(monkeypatch):
    # is_connected is False after any failed call_tool until the next call
    # reconnects. Pruning on that bit emptied the chat tool list for the
    # rest of the process (#809).
    monkeypatch.setattr(
        "core.integrations.mcp.client.process_mcp_client",
        lambda: _Client(connected=False),
    )
    monkeypatch.setattr(
        "core.integrations.mcp.registry.eager_connect_enabled", lambda: True
    )

    registry = MCPRegistry()
    registry.register_server("splunk-selfhosted", {}, [TOOL])
    assert registry.get_tool_names() == [FLAT]

    names = [t["name"] for t in live_mcp_tools(registry)]
    assert names == [FLAT]


def test_enable_then_disable_changes_tools_without_a_refresh():
    registry = MCPRegistry()
    client = _Client(connected=True)

    assert register_connected(registry, client, "splunk-selfhosted") is True
    assert registry.get_all_tools()[0]["name"] == FLAT

    deactivate(registry, "splunk-selfhosted")
    assert registry.get_all_tools() == []


def test_live_mcp_tools_does_not_revive_a_disabled_server(monkeypatch):
    # disconnect_from_server leaves tools_cache in place. A refresh that
    # still registered from the cache would undo disable.
    monkeypatch.setattr(
        "core.integrations.mcp.client.process_mcp_client",
        lambda: _Client(connected=False),
    )
    monkeypatch.setattr(
        "core.integrations.mcp.registry.eager_connect_enabled", lambda: True
    )

    registry = MCPRegistry()
    register_connected(registry, _Client(connected=True), "splunk-selfhosted")
    deactivate(registry, "splunk-selfhosted")

    assert [t["name"] for t in live_mcp_tools(registry)] == []


@pytest.mark.asyncio
async def test_execute_mcp_tool_reaches_a_runtime_enabled_server(monkeypatch):
    from core.agents.mcp_tools import execute_mcp_tool

    class _Callable(_Client):
        async def call_tool(self, server, tool, args, timeout=30.0):
            assert (server, tool) == ("splunk-selfhosted", "splunk_execute")
            return {"content": [{"type": "text", "text": '{"ok": true}'}]}

    client = _Callable(connected=True)
    monkeypatch.setattr(
        "core.integrations.mcp.client.process_mcp_client", lambda: client
    )

    registry = MCPRegistry()
    assert register_connected(registry, client, "splunk-selfhosted") is True

    rows, handled = await execute_mcp_tool(FLAT, {}, 5.0, registry)
    assert handled is True
    assert rows == [{"ok": True}]
