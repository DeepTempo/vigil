# The config layer a chat turn runs under. Assembled per request because which
# tools a conversation may reach depends on the agent the operator picked, and
# the agent registry lives on this side of the boundary.

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

import yaml

from core.llm.tool_schemas import ALL_TOOLS

REMOTE = "remote"

# A conversation is one answer at a time with a person waiting, so the ceiling is
# per turn rather than per run: they will say so long before a budget would.
DEFAULT_BUDGETS = {"max_calls": 12, "max_wall_ms": 300_000, "max_cost_usd": 2.0}
DEFAULT_RUNTIME = {"max_turns": 8, "result_cap": 20_000, "recall_limit": 3}

# A session id is the console's and is not a uuid; a run id is. Derived rather
# than generated so every turn of one conversation lands on the same run.
CONVERSATIONS = uuid.UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8")


def run_id_for(session_id: str) -> str:
    return str(uuid.uuid5(CONVERSATIONS, session_id))


# A tool with no description is dropped rather than declared: the agent layer
# refuses one, because a model cannot choose between two blank tools.
def _declare(wanted: Optional[List[str]]) -> List[Dict[str, Any]]:
    catalogue = {tool["name"]: tool for tool in ALL_TOOLS if tool.get("name")}
    names = list(catalogue) if wanted is None else [n for n in wanted if n in catalogue]
    declared = []
    for name in names:
        entry = catalogue[name]
        description = (entry.get("description") or "").strip()
        if not description:
            continue
        declared.append(
            {
                "id": name,
                "kind": REMOTE,
                "description": description,
                "parameters": entry.get("input_schema") or {"type": "object"},
            }
        )
    return declared


def chat_config(model: str, tools: Optional[List[str]] = None) -> str:
    document = {
        "model": model,
        "budgets": DEFAULT_BUDGETS,
        "runtime": DEFAULT_RUNTIME,
        "tools": _declare(tools),
        # A chat tool asks the person directly rather than parking on a
        # checkpoint: they are already in the conversation.
        "approvals": [],
        "thresholds": {},
    }
    return yaml.safe_dump(
        document, default_flow_style=False, sort_keys=False, allow_unicode=True
    )
