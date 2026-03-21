import asyncio
import json
import logging
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio
from core.config import get_integration_config

logger = logging.getLogger(__name__)
server = Server("gcp-security")


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


def get_client():
    try:
        from google.cloud import securitycenter
        config = get_integration_config('gcp_security')
        return securitycenter.SecurityCenterClient(), config.get('organization_id')
    except Exception:
        return None, None


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(name="gcp_get_findings", description="Get GCP Security Command Center findings",
            inputSchema={"type": "object", "properties": {
                "severity": {"type": "string"}, "limit": {"type": "integer", "default": 20}
            }, "required": []}),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    client, org_id = get_client()
    if not client or not org_id:
        return result({"error": "GCP Security not configured"})
    
    args = arguments or {}
    
    try:
        if name == "gcp_get_findings":
            parent = f"organizations/{org_id}/sources/-"
            filter_str = ""
            if sev := args.get("severity"):
                filter_str = f'severity="{sev.upper()}"'
            
            req = {"parent": parent, "filter": filter_str, "page_size": args.get("limit", 20)}
            response = client.list_findings(request=req)
            
            findings = []
            for f in response:
                finding = f.finding
                findings.append({
                    "name": finding.name, "category": finding.category,
                    "severity": str(finding.severity), "state": str(finding.state)
                })
            return result({"count": len(findings), "findings": findings})
        
        return result({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return result({"error": str(e)})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="gcp-security", server_version="0.1.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})
        ))


if __name__ == "__main__":
    asyncio.run(main())
