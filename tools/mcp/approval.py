import asyncio
import json
import logging

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions

logger = logging.getLogger(__name__)
server = Server("approval")


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


def get_approval_svc():
    from core.response.approval_service import (ActionStatus, ActionType,
                                                get_approval_service)

    return get_approval_service(), ActionType, ActionStatus


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(
            name="create_approval_action",
            description="Submit action to approval queue",
            inputSchema={
                "type": "object",
                "properties": {
                    "action_type": {
                        "type": "string",
                        "enum": [
                            "isolate_host",
                            "block_ip",
                            "block_domain",
                            "quarantine_file",
                            "disable_user",
                            "custom",
                        ],
                    },
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "target": {"type": "string"},
                    "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    "reason": {"type": "string"},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                    "created_by": {"type": "string", "default": "agent"},
                },
                "required": [
                    "action_type",
                    "title",
                    "description",
                    "target",
                    "confidence",
                    "reason",
                    "evidence",
                ],
            },
        ),
        types.Tool(
            name="list_approval_actions",
            description="List approval actions",
            inputSchema={
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": [
                            "pending",
                            "approved",
                            "rejected",
                            "executed",
                            "failed",
                        ],
                    },
                    "action_type": {"type": "string"},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="get_approval_action",
            description="Get action details",
            inputSchema={
                "type": "object",
                "properties": {"action_id": {"type": "string"}},
                "required": ["action_id"],
            },
        ),
        types.Tool(
            name="approve_action",
            description="Approve pending action",
            inputSchema={
                "type": "object",
                "properties": {
                    "action_id": {"type": "string"},
                    "approved_by": {"type": "string", "default": "analyst"},
                },
                "required": ["action_id"],
            },
        ),
        types.Tool(
            name="reject_action",
            description="Reject pending action",
            inputSchema={
                "type": "object",
                "properties": {
                    "action_id": {"type": "string"},
                    "reason": {"type": "string"},
                    "rejected_by": {"type": "string", "default": "analyst"},
                },
                "required": ["action_id", "reason"],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    try:
        svc, ActionType, ActionStatus = get_approval_svc()
    except Exception as e:
        return result({"error": f"Service error: {e}"})

    try:
        if name == "create_approval_action":
            args = arguments or {}
            required = [
                "action_type",
                "title",
                "description",
                "target",
                "confidence",
                "reason",
            ]
            if not all(args.get(k) is not None for k in required):
                return result(
                    {"error": "Missing required params", "required": required}
                )

            action = svc.create_action(
                action_type=ActionType(args["action_type"]),
                title=args["title"],
                description=args["description"],
                target=args["target"],
                confidence=args["confidence"],
                reason=args["reason"],
                evidence=args.get("evidence", []),
                created_by=args.get("created_by", "agent"),
            )
            msg = f"Action created. Status: {action.status}"
            if action.status == "approved":
                msg += f" (auto-approved, conf: {args['confidence']:.0%})"
            return result(
                {
                    "success": True,
                    "action_id": action.action_id,
                    "status": action.status,
                    "message": msg,
                }
            )

        elif name == "list_approval_actions":
            args = arguments or {}
            status = ActionStatus(args["status"]) if args.get("status") else None
            action_type = (
                ActionType(args["action_type"]) if args.get("action_type") else None
            )
            actions = svc.list_actions(status=status, action_type=action_type)
            return result(
                {
                    "success": True,
                    "count": len(actions),
                    "actions": [
                        {
                            "action_id": a.action_id,
                            "action_type": a.action_type,
                            "title": a.title,
                            "target": a.target,
                            "confidence": a.confidence,
                            "status": a.status,
                            "created_at": a.created_at,
                        }
                        for a in actions
                    ],
                }
            )

        elif name == "get_approval_action":
            aid = arguments.get("action_id") if arguments else None
            if not aid:
                return result({"error": "action_id required"})
            action = svc.get_action(aid)
            if not action:
                return result({"error": f"Action {aid} not found"})
            return result(
                {
                    "success": True,
                    "action": {
                        "action_id": action.action_id,
                        "action_type": action.action_type,
                        "title": action.title,
                        "description": action.description,
                        "target": action.target,
                        "confidence": action.confidence,
                        "reason": action.reason,
                        "evidence": action.evidence,
                        "status": action.status,
                        "created_at": action.created_at,
                        "approved_at": action.approved_at,
                        "approved_by": action.approved_by,
                    },
                }
            )

        elif name == "approve_action":
            aid = arguments.get("action_id") if arguments else None
            by = arguments.get("approved_by", "analyst") if arguments else "analyst"
            if not aid:
                return result({"error": "action_id required"})
            action = svc.approve_action(aid, by)
            if not action:
                return result({"error": f"Action {aid} not found"})
            return result({"success": True, "action_id": aid, "status": action.status})

        elif name == "reject_action":
            aid = arguments.get("action_id") if arguments else None
            reason = arguments.get("reason") if arguments else None
            by = arguments.get("rejected_by", "analyst") if arguments else "analyst"
            if not aid or not reason:
                return result({"error": "action_id and reason required"})
            action = svc.reject_action(aid, reason, by)
            if not action:
                return result({"error": f"Action {aid} not found"})
            return result({"success": True, "action_id": aid, "status": action.status})

        else:
            return result({"error": f"Unknown tool: {name}"})

    except Exception as e:
        return result({"error": str(e)})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(
            read,
            write,
            InitializationOptions(
                server_name="approval",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
