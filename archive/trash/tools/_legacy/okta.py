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
server = Server("okta")


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(name="okta_get_user", description="Get Okta user by email/id",
            inputSchema={"type": "object", "properties": {"user": {"type": "string"}}, "required": ["user"]}),
        types.Tool(name="okta_suspend_user", description="Suspend Okta user",
            inputSchema={"type": "object", "properties": {"user_id": {"type": "string"}, "reason": {"type": "string"}}, "required": ["user_id", "reason"]}),
        types.Tool(name="okta_get_logs", description="Get Okta system logs",
            inputSchema={"type": "object", "properties": {"filter": {"type": "string"}, "limit": {"type": "integer", "default": 20}}, "required": []}),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    config = get_integration_config('okta')
    domain = config.get('domain')
    token = config.get('api_token')
    if not domain or not token:
        return result({"error": "Okta not configured"})
    
    args = arguments or {}
    headers = {"Authorization": f"SSWS {token}", "Content-Type": "application/json"}
    base = f"https://{domain}/api/v1"
    
    try:
        if name == "okta_get_user":
            user = args.get("user")
            if not user:
                return result({"error": "user required"})
            resp = requests.get(f"{base}/users/{user}", headers=headers, timeout=30)
            if resp.status_code == 404:
                return result({"user": user, "found": False})
            resp.raise_for_status()
            data = resp.json()
            return result({
                "found": True, "id": data.get("id"),
                "status": data.get("status"),
                "profile": data.get("profile", {})
            })
        
        elif name == "okta_suspend_user":
            uid = args.get("user_id")
            if not uid:
                return result({"error": "user_id required"})
            resp = requests.post(f"{base}/users/{uid}/lifecycle/suspend", headers=headers, timeout=30)
            resp.raise_for_status()
            return result({"success": True, "user_id": uid, "action": "suspended"})
        
        elif name == "okta_get_logs":
            params = {"limit": args.get("limit", 20)}
            if args.get("filter"):
                params["filter"] = args["filter"]
            resp = requests.get(f"{base}/logs", headers=headers, params=params, timeout=30)
            resp.raise_for_status()
            logs = resp.json()
            return result({"count": len(logs), "logs": logs})
        
        return result({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return result({"error": str(e)})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="okta", server_version="0.1.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})
        ))


if __name__ == "__main__":
    asyncio.run(main())
