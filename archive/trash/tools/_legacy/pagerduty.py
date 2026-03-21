import asyncio
import json
import logging
import requests
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio
from core.config import get_integration_config

logger = logging.getLogger(__name__)
server = Server("pagerduty")


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(name="pd_trigger_incident", description="Trigger PagerDuty incident",
            inputSchema={"type": "object", "properties": {
                "title": {"type": "string"}, "details": {"type": "string"},
                "severity": {"type": "string", "enum": ["info", "warning", "error", "critical"]}
            }, "required": ["title", "details"]}),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    config = get_integration_config('pagerduty')
    key = config.get('routing_key') or config.get('integration_key')
    if not key:
        return result({"error": "PagerDuty not configured"})
    
    args = arguments or {}
    
    if name == "pd_trigger_incident":
        title = args.get("title")
        details = args.get("details")
        if not title or not details:
            return result({"error": "title and details required"})
        try:
            resp = requests.post("https://events.pagerduty.com/v2/enqueue",
                json={
                    "routing_key": key, "event_action": "trigger",
                    "payload": {
                        "summary": title, "source": "ai-soc",
                        "severity": args.get("severity", "error"),
                        "custom_details": {"details": details}
                    }
                }, timeout=30)
            data = resp.json()
            if data.get("status") == "success":
                return result({"success": True, "dedup_key": data.get("dedup_key")})
            return result({"error": data.get("message", "Failed")})
        except Exception as e:
            return result({"error": str(e)})
    
    return result({"error": f"Unknown tool: {name}"})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="pagerduty", server_version="0.1.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})
        ))


if __name__ == "__main__":
    asyncio.run(main())
