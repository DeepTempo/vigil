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
server = Server("sentinelone")


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(name="s1_get_threats", description="Get SentinelOne threats",
            inputSchema={"type": "object", "properties": {
                "limit": {"type": "integer", "default": 10}
            }, "required": []}),
        types.Tool(name="s1_get_agent", description="Get agent info by IP/hostname",
            inputSchema={"type": "object", "properties": {
                "ip": {"type": "string"}, "hostname": {"type": "string"}
            }, "required": []}),
        types.Tool(name="s1_isolate", description="Isolate endpoint",
            inputSchema={"type": "object", "properties": {
                "agent_id": {"type": "string"}, "reason": {"type": "string"}
            }, "required": ["agent_id", "reason"]}),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    config = get_integration_config('sentinelone')
    url = config.get('url')
    token = config.get('api_token')
    if not url or not token:
        return result({"error": "SentinelOne not configured"})
    
    args = arguments or {}
    headers = {"Authorization": f"ApiToken {token}", "Content-Type": "application/json"}
    
    try:
        if name == "s1_get_threats":
            resp = requests.get(f"{url}/web/api/v2.1/threats", headers=headers,
                params={"limit": args.get("limit", 10)}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            threats = [{
                "id": t.get("id"), "classification": t.get("classification"),
                "agentComputerName": t.get("agentComputerName"), "mitigationStatus": t.get("mitigationStatus")
            } for t in data.get("data", [])]
            return result({"count": len(threats), "threats": threats})
        
        elif name == "s1_get_agent":
            params = {}
            if args.get("ip"):
                params["networkInterfaceInet__contains"] = args["ip"]
            if args.get("hostname"):
                params["computerName__contains"] = args["hostname"]
            if not params:
                return result({"error": "ip or hostname required"})
            
            resp = requests.get(f"{url}/web/api/v2.1/agents", headers=headers, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            agents = data.get("data", [])
            return result({"count": len(agents), "agents": agents[:5]})
        
        elif name == "s1_isolate":
            aid = args.get("agent_id")
            if not aid:
                return result({"error": "agent_id required"})
            resp = requests.post(f"{url}/web/api/v2.1/agents/actions/disconnect", headers=headers,
                json={"filter": {"ids": [aid]}}, timeout=30)
            resp.raise_for_status()
            return result({"success": True, "agent_id": aid, "action": "isolated"})
        
        return result({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return result({"error": str(e)})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="sentinelone", server_version="0.1.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})
        ))


if __name__ == "__main__":
    asyncio.run(main())
