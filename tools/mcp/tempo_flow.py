import asyncio
import json
import logging

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions

logger = logging.getLogger(__name__)
server = Server("tempo-flow")


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(
            name="tempo_get_workflows",
            description="Get investigation workflows",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        types.Tool(
            name="tempo_run_workflow",
            description="Execute investigation workflow",
            inputSchema={
                "type": "object",
                "properties": {
                    "workflow_id": {"type": "string"},
                    "finding_id": {"type": "string"},
                },
                "required": ["workflow_id", "finding_id"],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    args = arguments or {}

    try:
        if name == "tempo_get_workflows":
            from pathlib import Path

            wf_file = (
                Path(__file__).parent.parent / "data" / "investigation_workflows.json"
            )
            if wf_file.exists():
                with open(wf_file) as f:
                    workflows = json.load(f)
                return result({"count": len(workflows), "workflows": workflows})
            return result({"count": 0, "workflows": []})

        elif name == "tempo_run_workflow":
            wf_id = args.get("workflow_id")
            fid = args.get("finding_id")
            if not wf_id or not fid:
                return result({"error": "workflow_id and finding_id required"})
            # Stub - in production this would orchestrate the workflow
            return result(
                {
                    "success": True,
                    "workflow_id": wf_id,
                    "finding_id": fid,
                    "status": "initiated",
                    "message": "Workflow execution started",
                }
            )

        return result({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return result({"error": str(e)})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(
            read,
            write,
            InitializationOptions(
                server_name="tempo-flow",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
