import asyncio
import json
import logging
from urllib.parse import urlparse
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio

logger = logging.getLogger(__name__)
server = Server("url-analysis")


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(name="analyze_url", description="Analyze URL for security indicators",
            inputSchema={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}),
        types.Tool(name="extract_iocs", description="Extract IOCs from URL",
            inputSchema={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    args = arguments or {}
    
    if name == "analyze_url":
        url = args.get("url")
        if not url:
            return result({"error": "url required"})
        try:
            parsed = urlparse(url)
            analysis = {
                "url": url, "scheme": parsed.scheme, "domain": parsed.netloc,
                "path": parsed.path, "suspicious_indicators": []
            }
            if parsed.scheme != "https":
                analysis["suspicious_indicators"].append("Non-HTTPS")
            if any(c in parsed.netloc for c in ['@', ':', '%']):
                analysis["suspicious_indicators"].append("Suspicious characters in domain")
            if len(parsed.path) > 100:
                analysis["suspicious_indicators"].append("Unusually long path")
            return result(analysis)
        except Exception as e:
            return result({"error": str(e)})
    
    elif name == "extract_iocs":
        url = args.get("url")
        if not url:
            return result({"error": "url required"})
        try:
            parsed = urlparse(url)
            return result({
                "url": url,
                "iocs": {
                    "domain": parsed.netloc.split(':')[0] if parsed.netloc else None,
                    "ip": None,
                    "port": parsed.port,
                    "path": parsed.path
                }
            })
        except Exception as e:
            return result({"error": str(e)})
    
    return result({"error": f"Unknown tool: {name}"})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="url-analysis", server_version="0.1.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})
        ))


if __name__ == "__main__":
    asyncio.run(main())
