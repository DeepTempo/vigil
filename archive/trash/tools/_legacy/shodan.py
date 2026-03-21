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
server = Server("shodan")


def get_config():
    return get_integration_config('shodan')


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(name="shodan_search_ip", description="Search IP in Shodan",
            inputSchema={"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}),
        types.Tool(name="shodan_search_exploits", description="Search exploits for CVE/product",
            inputSchema={"type": "object", "properties": {
                "query": {"type": "string"}, "limit": {"type": "integer", "default": 10}
            }, "required": ["query"]}),
        types.Tool(name="shodan_search_vulns", description="Find hosts vulnerable to CVE",
            inputSchema={"type": "object", "properties": {
                "cve": {"type": "string"}, "limit": {"type": "integer", "default": 10}
            }, "required": ["cve"]}),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    config = get_config()
    api_key = config.get('api_key')
    if not api_key:
        return result({"error": "Shodan not configured"})
    
    try:
        if name == "shodan_search_ip":
            ip = arguments.get("ip")
            if not ip:
                return result({"error": "ip required"})
            resp = requests.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": api_key}, timeout=30)
            if resp.status_code == 404:
                return result({"ip": ip, "found": False})
            resp.raise_for_status()
            data = resp.json()
            return result({
                "ip": ip, "found": True,
                "hostnames": data.get("hostnames", []),
                "org": data.get("org"),
                "country": data.get("country_name"),
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
                "services": [{
                    "port": s.get("port"), "product": s.get("product"),
                    "version": s.get("version"), "banner": s.get("data", "")[:200]
                } for s in data.get("data", [])[:5]]
            })
        
        elif name == "shodan_search_exploits":
            query = arguments.get("query")
            limit = arguments.get("limit", 10)
            if not query:
                return result({"error": "query required"})
            resp = requests.get("https://exploits.shodan.io/api/search", params={"key": api_key, "query": query}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return result({
                "query": query, "total": data.get("total", 0),
                "exploits": [{
                    "id": e.get("_id"), "description": e.get("description", "")[:200],
                    "platform": e.get("platform"), "cve": e.get("cve", [])
                } for e in data.get("matches", [])[:limit]]
            })
        
        elif name == "shodan_search_vulns":
            cve = arguments.get("cve")
            limit = arguments.get("limit", 10)
            if not cve:
                return result({"error": "cve required"})
            resp = requests.get("https://api.shodan.io/shodan/host/search", params={"key": api_key, "query": f"vuln:{cve}"}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return result({
                "cve": cve, "total": data.get("total", 0),
                "hosts": [{
                    "ip": m.get("ip_str"), "port": m.get("port"),
                    "org": m.get("org"), "country": m.get("location", {}).get("country_name")
                } for m in data.get("matches", [])[:limit]]
            })
        
        else:
            return result({"error": f"Unknown tool: {name}"})
    
    except requests.exceptions.HTTPError as e:
        return result({"error": "API error", "status": e.response.status_code if hasattr(e, 'response') else None})
    except Exception as e:
        return result({"error": str(e)})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="shodan", server_version="0.1.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})
        ))


if __name__ == "__main__":
    asyncio.run(main())
