"""Registry tracks intent (enabled), not the last call_tool's is_connected bit (#809)."""

from __future__ import annotations

import pytest

from core.agents.mcp_tools import execute_mcp_tool
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


class _Client:
    mcp_service = None
    tools_cache = {"splunk-selfhosted": [TOOL]}

    def __init__(self, connected=False):
        self._connected = connected

    def get_connection_status(self):
        return {"splunk-selfhosted": self._connected}


def _register(registry=None, client=None):
    registry = registry or MCPRegistry()
    client = client or _Client(connected=True)
    assert register_connected(registry, client, "splunk-selfhosted")
    return registry, client


def test_dropped_session_still_appears_in_live_mcp_tools(monkeypatch):
    # The bug: is_connected is False after any failed call_tool, refresh pruned
    # the server, and chat never offered it again so nothing could reconnect.
    monkeypatch.setattr(
        "core.integrations.mcp.registry.eager_connect_enabled", lambda: True
    )
    monkeypatch.setattr(
        "core.integrations.mcp.client.process_mcp_client", lambda: _Client(False)
    )

    registry = MCPRegistry()
    registry.register_server("splunk-selfhosted", {}, [TOOL])
    assert registry.get_tool_names() == ["splunk-selfhosted_splunk_execute"]

    names = [t["name"] for t in live_mcp_tools(registry)]
    assert names == ["splunk-selfhosted_splunk_execute"]


def test_enable_makes_tools_visible_without_refresh():
    registry, _ = _register()
    assert [t["name"] for t in registry.get_all_tools()] == [
        "splunk-selfhosted_splunk_execute"
    ]


def test_disable_hides_tools_without_refresh():
    registry, _ = _register()
    deactivate(registry, "splunk-selfhosted")
    assert registry.get_all_tools() == []


def test_disabled_server_is_not_resurrected_by_live_refresh(monkeypatch):
    # disconnect_from_server leaves tools_cache; without deactivate the old
    # prune-on-read hide would be gone and disable would leak tools into chat.
    monkeypatch.setattr(
        "core.integrations.mcp.registry.eager_connect_enabled", lambda: True
    )
    monkeypatch.setattr(
        "core.integrations.mcp.client.process_mcp_client", lambda: _Client(False)
    )

    registry, _ = _register()
    deactivate(registry, "splunk-selfhosted")
    assert [t["name"] for t in live_mcp_tools(registry)] == []


@pytest.mark.asyncio
async def test_execute_mcp_tool_after_runtime_enable_without_a_resolve(monkeypatch):
    registry, client = _register()

    async def _call(server, tool, args, timeout=30.0):
        assert (server, tool, args) == ("splunk-selfhosted", "splunk_execute", {})
        return {"content": [{"type": "text", "text": '{"ok": true}'}]}

    client.call_tool = _call
    monkeypatch.setattr(
        "core.integrations.mcp.client.process_mcp_client", lambda: client
    )

    rows, handled = await execute_mcp_tool(
        "splunk-selfhosted_splunk_execute", {}, 5.0, registry
    )
    assert handled is True
    assert rows == [{"ok": True}]
