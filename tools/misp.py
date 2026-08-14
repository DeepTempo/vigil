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
server = Server("misp")


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


def get_config():
    return get_integration_config('misp')


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(name="misp_search_ioc", description="Search IOC in MISP",
            inputSchema={"type": "object", "properties": {
                "value": {"type": "string"}, "type": {"type": "string"}
            }, "required": ["value"]}),
        types.Tool(name="misp_get_events", description="Get recent MISP events",
            inputSchema={"type": "object", "properties": {"limit": {"type": "integer", "default": 10}}, "required": []}),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    config = get_config()
    api_key = config.get('api_key')
    url = config.get('url')
    if not api_key or not url:
        return result({"error": "MISP not configured"})

    args = arguments or {}
    headers = {"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"}
    
    try:
        if name == "misp_search_ioc":
            value = args.get("value")
            if not value:
                return result({"error": "value required"})
            resp = requests.post(f"{url}/attributes/restSearch", headers=headers, 
                json={"value": value}, timeout=30, verify=config.get('verify_ssl', True))
            resp.raise_for_status()
            data = resp.json()
            attrs = data.get("response", {}).get("Attribute", [])
            return result({"value": value, "found": len(attrs) > 0, "count": len(attrs), "attributes": attrs[:10]})
        
        elif name == "misp_get_events":
            limit = args.get("limit", 10)
            resp = requests.post(f"{url}/events/restSearch", headers=headers,
                json={"limit": limit, "returnFormat": "json"}, timeout=30, verify=config.get('verify_ssl', True))
            resp.raise_for_status()
            data = resp.json()
            events = data.get("response", [])
            return result({"count": len(events), "events": [{
                "id": e.get("Event", {}).get("id"),
                "info": e.get("Event", {}).get("info"),
                "date": e.get("Event", {}).get("date")
            } for e in events[:limit]]})
        
        return result({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return result({"error": str(e)})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="misp", server_version="0.1.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})
        ))


if __name__ == "__main__":
    asyncio.run(main())
