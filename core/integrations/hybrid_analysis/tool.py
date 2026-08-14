import asyncio
import json
import logging
import requests
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio
from core.integrations._base.config import resolve
from core.integrations.hybrid_analysis.descriptor import HYBRID_ANALYSIS

logger = logging.getLogger(__name__)
server = Server("hybrid-analysis")


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(name="ha_search_hash", description="Search Hybrid Analysis by file hash",
            inputSchema={"type": "object", "properties": {"hash": {"type": "string"}}, "required": ["hash"]}),
        types.Tool(name="ha_get_report", description="Get analysis report",
            inputSchema={"type": "object", "properties": {"job_id": {"type": "string"}}, "required": ["job_id"]}),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    config = resolve(HYBRID_ANALYSIS)
    api_key = config.get('api_key')
    if not api_key:
        return result({"error": "Hybrid Analysis not configured"})
    
    args = arguments or {}
    headers = {"api-key": api_key, "User-Agent": "Falcon Sandbox"}
    
    try:
        if name == "ha_search_hash":
            h = args.get("hash")
            if not h:
                return result({"error": "hash required"})
            resp = requests.post("https://www.hybrid-analysis.com/api/v2/search/hash", headers=headers,
                data={"hash": h}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return result({"hash": h, "found": len(data) > 0, "results": data[:5]})
        
        elif name == "ha_get_report":
            jid = args.get("job_id")
            if not jid:
                return result({"error": "job_id required"})
            resp = requests.get(f"https://www.hybrid-analysis.com/api/v2/report/{jid}/summary", headers=headers, timeout=30)
            resp.raise_for_status()
            return result({"job_id": jid, "report": resp.json()})
        
        return result({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return result({"error": str(e)})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="hybrid-analysis", server_version="0.1.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})
        ))


if __name__ == "__main__":
    asyncio.run(main())
