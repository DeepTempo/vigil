import asyncio
import json
import logging
import requests
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio

logger = logging.getLogger(__name__)
server = Server("ip-geolocation")


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(
            name="geolocate_ip",
            description="Get geolocation for IP address",
            inputSchema={
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        ),
        types.Tool(
            name="geolocate_batch",
            description="Geolocate multiple IPs",
            inputSchema={
                "type": "object",
                "properties": {"ips": {"type": "array", "items": {"type": "string"}}},
                "required": ["ips"],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    args = arguments or {}

    def lookup_ip(ip):
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "ip": ip,
                        "country": data.get("country"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                    }
            return {"ip": ip, "error": "Lookup failed"}
        except Exception as e:
            return {"ip": ip, "error": str(e)}

    if name == "geolocate_ip":
        ip = args.get("ip")
        if not ip:
            return result({"error": "ip required"})
        return result(lookup_ip(ip))

    elif name == "geolocate_batch":
        ips = args.get("ips", [])
        if not ips:
            return result({"error": "ips required"})
        results = [lookup_ip(ip) for ip in ips[:10]]
        return result({"count": len(results), "results": results})

    return result({"error": f"Unknown tool: {name}"})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(
            read,
            write,
            InitializationOptions(
                server_name="ip-geolocation",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
