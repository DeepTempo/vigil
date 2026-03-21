import asyncio
import json
import logging
import time
import base64
import requests
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio
from core.config import get_integration_config
from core.rate_limit import RateLimiter

logger = logging.getLogger(__name__)
server = Server("virustotal")
limiter = RateLimiter(requests_per_minute=4)


def get_config():
    return get_integration_config('virustotal')


def api_call(endpoint, api_key, timeout=30):
    limiter.acquire_sync()
    headers = {"x-apikey": api_key}
    resp = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}", headers=headers, timeout=timeout)
    return resp


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(name="vt_check_hash", description="Check file hash reputation",
            inputSchema={"type": "object", "properties": {"hash": {"type": "string"}}, "required": ["hash"]}),
        types.Tool(name="vt_check_ip", description="Check IP reputation",
            inputSchema={"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}),
        types.Tool(name="vt_check_domain", description="Check domain reputation",
            inputSchema={"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}),
        types.Tool(name="vt_check_url", description="Check URL reputation",
            inputSchema={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    config = get_config()
    api_key = config.get('api_key')
    if not api_key:
        return result({"error": "VirusTotal not configured"})
    
    try:
        if name == "vt_check_hash":
            h = arguments.get("hash")
            if not h:
                return result({"error": "hash required"})
            resp = api_call(f"files/{h}", api_key)
            if resp.status_code == 404:
                return result({"hash": h, "found": False})
            resp.raise_for_status()
            data = resp.json()
            attr = data.get('data', {}).get('attributes', {})
            stats = attr.get('last_analysis_stats', {})
            return result({
                "hash": h, "found": True,
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "total_engines": sum(stats.values()),
                "names": attr.get('names', [])[:5],
                "file_type": attr.get('type_description'),
                "reputation": attr.get('reputation', 0)
            })
        
        elif name == "vt_check_ip":
            ip = arguments.get("ip")
            if not ip:
                return result({"error": "ip required"})
            resp = api_call(f"ip_addresses/{ip}", api_key)
            resp.raise_for_status()
            data = resp.json()
            attr = data.get('data', {}).get('attributes', {})
            stats = attr.get('last_analysis_stats', {})
            return result({
                "ip": ip,
                "malicious": stats.get('malicious', 0),
                "asn": attr.get('asn'),
                "country": attr.get('country'),
                "reputation": attr.get('reputation', 0)
            })
        
        elif name == "vt_check_domain":
            domain = arguments.get("domain")
            if not domain:
                return result({"error": "domain required"})
            resp = api_call(f"domains/{domain}", api_key)
            resp.raise_for_status()
            data = resp.json()
            attr = data.get('data', {}).get('attributes', {})
            stats = attr.get('last_analysis_stats', {})
            return result({
                "domain": domain,
                "malicious": stats.get('malicious', 0),
                "categories": attr.get('categories', {}),
                "reputation": attr.get('reputation', 0)
            })
        
        elif name == "vt_check_url":
            url = arguments.get("url")
            if not url:
                return result({"error": "url required"})
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            resp = api_call(f"urls/{url_id}", api_key)
            if resp.status_code == 404:
                return result({"url": url, "found": False})
            resp.raise_for_status()
            data = resp.json()
            attr = data.get('data', {}).get('attributes', {})
            stats = attr.get('last_analysis_stats', {})
            return result({
                "url": url, "found": True,
                "malicious": stats.get('malicious', 0),
                "reputation": attr.get('reputation', 0)
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
            server_name="virustotal", server_version="0.1.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})
        ))


if __name__ == "__main__":
    asyncio.run(main())
