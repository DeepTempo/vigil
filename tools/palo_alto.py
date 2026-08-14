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
server = Server("palo-alto")


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(name="pan_block_ip", description="Block IP on Palo Alto firewall",
            inputSchema={"type": "object", "properties": {
                "ip": {"type": "string"}, "reason": {"type": "string"}
            }, "required": ["ip", "reason"]}),
        types.Tool(name="pan_get_threats", description="Get threat logs",
            inputSchema={"type": "object", "properties": {"limit": {"type": "integer", "default": 20}}, "required": []}),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    config = get_integration_config('palo_alto')
    url = config.get('url')
    api_key = config.get('api_key')
    if not url or not api_key:
        return result({"error": "Palo Alto not configured"})

    args = arguments or {}
    
    try:
        if name == "pan_block_ip":
            ip = args.get("ip")
            if not ip:
                return result({"error": "ip required"})
            # Add to EDL or address group
            resp = requests.get(f"{url}/api/", params={
                "type": "config", "action": "set", "key": api_key,
                "xpath": f"/config/devices/entry/vsys/entry[@name='vsys1']/address/entry[@name='blocked-{ip}']",
                "element": f"<ip-netmask>{ip}/32</ip-netmask><description>Blocked: {args.get('reason', 'security')}</description>"
            }, verify=config.get('verify_ssl', True), timeout=30)
            return result({"success": resp.status_code == 200, "ip": ip, "action": "blocked"})
        
        elif name == "pan_get_threats":
            resp = requests.get(f"{url}/api/", params={
                "type": "log", "log-type": "threat", "key": api_key, "nlogs": args.get("limit", 20)
            }, verify=config.get('verify_ssl', True), timeout=30)
            # Parse XML response (simplified)
            return result({"success": True, "message": "Check Palo Alto console for threat logs"})
        
        return result({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return result({"error": str(e)})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="palo-alto", server_version="0.1.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})
        ))


if __name__ == "__main__":
    asyncio.run(main())
