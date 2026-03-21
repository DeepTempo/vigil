import asyncio
import json
import logging
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio
from core.config import get_integration_config

logger = logging.getLogger(__name__)
server = Server("aws-security-hub")


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


def get_client():
    try:
        import boto3
        config = get_integration_config('aws_security_hub')
        return boto3.client('securityhub',
            aws_access_key_id=config.get('access_key'),
            aws_secret_access_key=config.get('secret_key'),
            region_name=config.get('region', 'us-east-1'))
    except Exception:
        return None


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(name="aws_sh_get_findings", description="Get AWS Security Hub findings",
            inputSchema={"type": "object", "properties": {
                "severity": {"type": "string"}, "limit": {"type": "integer", "default": 20}
            }, "required": []}),
        types.Tool(name="aws_sh_get_insights", description="Get Security Hub insights",
            inputSchema={"type": "object", "properties": {}, "required": []}),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    client = get_client()
    if not client:
        return result({"error": "AWS Security Hub not configured"})
    
    args = arguments or {}
    
    try:
        if name == "aws_sh_get_findings":
            filters = {}
            if sev := args.get("severity"):
                filters["SeverityLabel"] = [{"Value": sev.upper(), "Comparison": "EQUALS"}]
            resp = client.get_findings(Filters=filters, MaxResults=args.get("limit", 20))
            findings = [{
                "id": f.get("Id"), "title": f.get("Title"),
                "severity": f.get("Severity", {}).get("Label"),
                "status": f.get("Workflow", {}).get("Status")
            } for f in resp.get("Findings", [])]
            return result({"count": len(findings), "findings": findings})
        
        elif name == "aws_sh_get_insights":
            resp = client.get_insights()
            insights = [{"arn": i.get("InsightArn"), "name": i.get("Name")} for i in resp.get("Insights", [])]
            return result({"count": len(insights), "insights": insights})
        
        return result({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return result({"error": str(e)})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="aws-security-hub", server_version="0.1.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})
        ))


if __name__ == "__main__":
    asyncio.run(main())
