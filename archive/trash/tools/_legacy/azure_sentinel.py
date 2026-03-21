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
server = Server("azure-sentinel")


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


def get_token():
    config = get_integration_config('azure_sentinel')
    tenant = config.get('tenant_id')
    client_id = config.get('client_id')
    client_secret = config.get('client_secret')
    if not all([tenant, client_id, client_secret]):
        return None, config
    try:
        resp = requests.post(f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials", "client_id": client_id,
                "client_secret": client_secret, "scope": "https://management.azure.com/.default"
            }, timeout=30)
        resp.raise_for_status()
        return resp.json().get("access_token"), config
    except Exception:
        return None, config


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(name="sentinel_get_incidents", description="Get Azure Sentinel incidents",
            inputSchema={"type": "object", "properties": {"limit": {"type": "integer", "default": 20}}, "required": []}),
        types.Tool(name="sentinel_run_query", description="Run KQL query in Sentinel",
            inputSchema={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    token, config = get_token()
    if not token:
        return result({"error": "Azure Sentinel not configured"})
    
    args = arguments or {}
    headers = {"Authorization": f"Bearer {token}"}
    sub = config.get('subscription_id')
    rg = config.get('resource_group')
    ws = config.get('workspace_name')
    base = f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}"
    
    try:
        if name == "sentinel_get_incidents":
            resp = requests.get(f"{base}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01",
                headers=headers, timeout=30)
            resp.raise_for_status()
            incidents = [{
                "id": i.get("name"), "title": i.get("properties", {}).get("title"),
                "severity": i.get("properties", {}).get("severity"),
                "status": i.get("properties", {}).get("status")
            } for i in resp.json().get("value", [])[:args.get("limit", 20)]]
            return result({"count": len(incidents), "incidents": incidents})
        
        elif name == "sentinel_run_query":
            query = args.get("query")
            if not query:
                return result({"error": "query required"})
            resp = requests.post(f"{base}/api/query?api-version=2017-01-01-preview",
                headers={**headers, "Content-Type": "application/json"},
                json={"query": query}, timeout=60)
            resp.raise_for_status()
            return result({"success": True, "results": resp.json()})
        
        return result({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return result({"error": str(e)})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="azure-sentinel", server_version="0.1.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})
        ))


if __name__ == "__main__":
    asyncio.run(main())
