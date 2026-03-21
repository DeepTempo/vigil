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
server = Server("cribl-stream")


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(name="cribl_get_pipelines", description="Get Cribl Stream pipelines",
            inputSchema={"type": "object", "properties": {}, "required": []}),
        types.Tool(name="cribl_get_sources", description="Get data sources",
            inputSchema={"type": "object", "properties": {}, "required": []}),
        types.Tool(name="cribl_get_destinations", description="Get data destinations",
            inputSchema={"type": "object", "properties": {}, "required": []}),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    config = get_integration_config('cribl_stream')
    url = config.get('url')
    token = config.get('token')
    if not url or not token:
        return result({"error": "Cribl Stream not configured"})
    
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    try:
        if name == "cribl_get_pipelines":
            resp = requests.get(f"{url}/api/v1/pipelines", headers=headers, timeout=30)
            resp.raise_for_status()
            pipelines = resp.json().get("items", [])
            return result({"count": len(pipelines), "pipelines": [{"id": p.get("id"), "conf": p.get("conf")} for p in pipelines]})
        
        elif name == "cribl_get_sources":
            resp = requests.get(f"{url}/api/v1/inputs", headers=headers, timeout=30)
            resp.raise_for_status()
            sources = resp.json().get("items", [])
            return result({"count": len(sources), "sources": [{"id": s.get("id"), "type": s.get("type")} for s in sources]})
        
        elif name == "cribl_get_destinations":
            resp = requests.get(f"{url}/api/v1/outputs", headers=headers, timeout=30)
            resp.raise_for_status()
            dests = resp.json().get("items", [])
            return result({"count": len(dests), "destinations": [{"id": d.get("id"), "type": d.get("type")} for d in dests]})
        
        return result({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return result({"error": str(e)})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="cribl-stream", server_version="0.1.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})
        ))


if __name__ == "__main__":
    asyncio.run(main())
