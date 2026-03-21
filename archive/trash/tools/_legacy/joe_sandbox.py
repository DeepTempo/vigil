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
server = Server("joe-sandbox")


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(name="joe_search", description="Search Joe Sandbox by hash/URL",
            inputSchema={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}),
        types.Tool(name="joe_get_report", description="Get analysis report",
            inputSchema={"type": "object", "properties": {"webid": {"type": "string"}}, "required": ["webid"]}),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    config = get_integration_config('joe_sandbox')
    api_key = config.get('api_key')
    url = config.get('url', 'https://jbxcloud.joesecurity.org/api')
    if not api_key:
        return result({"error": "Joe Sandbox not configured"})
    
    args = arguments or {}
    
    try:
        if name == "joe_search":
            query = args.get("query")
            if not query:
                return result({"error": "query required"})
            resp = requests.post(f"{url}/v2/analysis/search", data={"apikey": api_key, "q": query}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return result({"query": query, "found": len(data.get("data", [])) > 0, "results": data.get("data", [])[:5]})
        
        elif name == "joe_get_report":
            webid = args.get("webid")
            if not webid:
                return result({"error": "webid required"})
            resp = requests.post(f"{url}/v2/analysis/info", data={"apikey": api_key, "webid": webid}, timeout=30)
            resp.raise_for_status()
            return result({"webid": webid, "report": resp.json().get("data", {})})
        
        return result({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return result({"error": str(e)})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="joe-sandbox", server_version="0.1.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})
        ))


if __name__ == "__main__":
    asyncio.run(main())
