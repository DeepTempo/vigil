import asyncio
import json
import logging
import requests
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio
from core.integrations._base.config import resolve
from core.integrations.azure_ad.descriptor import AZURE_AD

logger = logging.getLogger(__name__)
server = Server("azure-ad")


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


def get_token():
    config = resolve(AZURE_AD)
    tenant = config.get('tenant_id')
    client_id = config.get('client_id')
    client_secret = config.get('client_secret')
    if not all([tenant, client_id, client_secret]):
        return None
    try:
        resp = requests.post(f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials", "client_id": client_id,
                "client_secret": client_secret, "scope": "https://graph.microsoft.com/.default"
            }, timeout=30)
        resp.raise_for_status()
        return resp.json().get("access_token")
    except Exception:
        return None


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(name="aad_get_user", description="Get Azure AD user",
            inputSchema={"type": "object", "properties": {"user": {"type": "string"}}, "required": ["user"]}),
        types.Tool(name="aad_disable_user", description="Disable Azure AD user",
            inputSchema={"type": "object", "properties": {"user_id": {"type": "string"}, "reason": {"type": "string"}}, "required": ["user_id", "reason"]}),
        types.Tool(name="aad_get_sign_ins", description="Get user sign-in logs",
            inputSchema={"type": "object", "properties": {"user": {"type": "string"}, "limit": {"type": "integer", "default": 20}}, "required": []}),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    token = get_token()
    if not token:
        return result({"error": "Azure AD not configured"})
    
    args = arguments or {}
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    try:
        if name == "aad_get_user":
            user = args.get("user")
            if not user:
                return result({"error": "user required"})
            resp = requests.get(f"https://graph.microsoft.com/v1.0/users/{user}", headers=headers, timeout=30)
            if resp.status_code == 404:
                return result({"user": user, "found": False})
            resp.raise_for_status()
            data = resp.json()
            return result({
                "found": True, "id": data.get("id"), "displayName": data.get("displayName"),
                "accountEnabled": data.get("accountEnabled"), "mail": data.get("mail")
            })
        
        elif name == "aad_disable_user":
            uid = args.get("user_id")
            if not uid:
                return result({"error": "user_id required"})
            resp = requests.patch(f"https://graph.microsoft.com/v1.0/users/{uid}",
                headers=headers, json={"accountEnabled": False}, timeout=30)
            resp.raise_for_status()
            return result({"success": True, "user_id": uid, "action": "disabled"})
        
        elif name == "aad_get_sign_ins":
            params = {"$top": args.get("limit", 20)}
            if user := args.get("user"):
                params["$filter"] = f"userPrincipalName eq '{user}'"
            resp = requests.get("https://graph.microsoft.com/v1.0/auditLogs/signIns",
                headers=headers, params=params, timeout=30)
            resp.raise_for_status()
            logs = resp.json().get("value", [])
            return result({"count": len(logs), "sign_ins": logs})
        
        return result({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return result({"error": str(e)})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="azure-ad", server_version="0.1.0",
            capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})
        ))


if __name__ == "__main__":
    asyncio.run(main())
