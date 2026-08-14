import asyncio
import json
import logging
import requests
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio
from core.integrations._base.config import resolve
from core.integrations.anyrun.descriptor import ANYRUN

logger = logging.getLogger(__name__)
server = Server("anyrun")


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(name="anyrun_get_report", description="Get Any.Run sandbox analysis report",
            inputSchema={"type": "object", "properties": {"task_id": {"type": "string"}}, "required": ["task_id"]}),
        types.Tool(name="anyrun_search_hash", description="Search Any.Run by file hash",
            inputSchema={"type": "object", "properties": {"hash": {"type": "string"}}, "required": ["hash"]}),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    config = resolve(ANYRUN)
    api_key = config.get('api_key')
    if not api_key:
        return result({"error": "Any.Run not configured"})
    
    args = arguments or {}
    headers = {"Authorization": f"API-Key {api_key}"}
    
    try:
        if name == "anyrun_get_report":
            tid = args.get("task_id")
            if not tid:
                return result({"error": "task_id required"})
            resp = requests.get(f"https://api.any.run/v1/analysis/{tid}", headers=headers, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            return result({"task_id": tid, "status": data.get("status"), "analysis": data.get("data", {})})
        
        elif name == "anyrun_search_hash":
            h = args.get("hash")
            if not h:
                return result({"error": "hash required"})
            resp = requests.get(f"https://api.any.run/v1/tasks", headers=headers,
                params={"hash": h}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            tasks = data.get("data", {}).get("tasks", [])
            return result({"hash": h, "found": len(tasks) > 0, "tasks": tasks[:5]})
        
        return result({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return result({"error": str(e)})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="anyrun", server_version="0.1.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})
        ))


if __name__ == "__main__":
    asyncio.run(main())
