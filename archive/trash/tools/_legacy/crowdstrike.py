import asyncio
import json
import logging
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio
from core.config import get_integration_config

logger = logging.getLogger(__name__)
server = Server("crowdstrike")

ISOLATED_HOSTS = set()
MOCK_ALERTS = {
    "192.168.1.100": [{"alert_id": "cs-001", "severity": "critical", "detection_type": "Malware", "hostname": "WORKSTATION-01"}],
    "10.0.0.50": [{"alert_id": "cs-002", "severity": "high", "detection_type": "Intrusion", "hostname": "SERVER-DMZ-01"}],
}


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(name="cs_get_alerts", description="Get CrowdStrike alerts for IP",
            inputSchema={"type": "object", "properties": {
                "ip_address": {"type": "string"}, "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]}
            }, "required": ["ip_address"]}),
        types.Tool(name="cs_isolate_host", description="Isolate host (requires confidence >= 0.85)",
            inputSchema={"type": "object", "properties": {
                "ip_address": {"type": "string"}, "reason": {"type": "string"},
                "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0}
            }, "required": ["ip_address", "reason", "confidence"]}),
        types.Tool(name="cs_unisolate_host", description="Remove isolation from host",
            inputSchema={"type": "object", "properties": {
                "ip_address": {"type": "string"}, "reason": {"type": "string"}
            }, "required": ["ip_address", "reason"]}),
        types.Tool(name="cs_host_status", description="Get host isolation status",
            inputSchema={"type": "object", "properties": {"ip_address": {"type": "string"}}, "required": ["ip_address"]}),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    args = arguments or {}
    
    if name == "cs_get_alerts":
        ip = args.get("ip_address")
        if not ip:
            return result({"error": "ip_address required"})
        alerts = MOCK_ALERTS.get(ip, [])
        if sev := args.get("severity"):
            alerts = [a for a in alerts if a.get("severity") == sev]
        return result({"ip_address": ip, "alerts": alerts, "total": len(alerts), "isolated": ip in ISOLATED_HOSTS})
    
    elif name == "cs_isolate_host":
        ip, reason, conf = args.get("ip_address"), args.get("reason"), args.get("confidence", 0)
        if not ip or not reason:
            return result({"error": "ip_address and reason required"})
        if conf < 0.85:
            return result({"error": "Confidence too low", "threshold": 0.85, "provided": conf})
        if ip in ISOLATED_HOSTS:
            return result({"status": "already_isolated", "ip_address": ip})
        ISOLATED_HOSTS.add(ip)
        return result({"status": "success", "action": "isolated", "ip_address": ip, "confidence": conf})
    
    elif name == "cs_unisolate_host":
        ip, reason = args.get("ip_address"), args.get("reason")
        if not ip or not reason:
            return result({"error": "ip_address and reason required"})
        if ip not in ISOLATED_HOSTS:
            return result({"status": "not_isolated", "ip_address": ip})
        ISOLATED_HOSTS.discard(ip)
        return result({"status": "success", "action": "unisolated", "ip_address": ip})
    
    elif name == "cs_host_status":
        ip = args.get("ip_address")
        if not ip:
            return result({"error": "ip_address required"})
        alerts = MOCK_ALERTS.get(ip, [])
        return result({
            "ip_address": ip, "isolated": ip in ISOLATED_HOSTS,
            "active_alerts": len(alerts),
            "highest_severity": max([a.get("severity", "none") for a in alerts], default="none")
        })
    
    return result({"error": f"Unknown tool: {name}"})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="crowdstrike", server_version="0.1.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})
        ))


if __name__ == "__main__":
    asyncio.run(main())
