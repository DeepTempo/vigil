#!/usr/bin/env python3
# Gates the count the architecture document opens with: five tool-calling loops in
# Python, now zero. The loop lives in the TypeScript harness and nowhere else.
#
# Detects the pattern rather than the names, because each new loop looks
# reasonable on its own and review does not catch the fifth one: a function that
# calls a provider inside a loop, reads tool calls off the response, and goes
# round again.

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCAN = ("core", "services", "tools", "scripts")
SKIP = ("__pycache__", "node_modules", "venv", ".venv", "tests")

# Where a completion is asked for. Attribute chains, matched on the tail so both
# client.messages.create and self.async_client.messages.create count.
PROVIDER_CALLS = (
    ("messages", "create"),
    ("chat", "completions", "create"),
    ("completions", "create"),
)

# What makes it a *tool* loop rather than a retry: the response is inspected for
# tool calls and the conversation grows by what they returned.
TOOL_SIGNALS = ("tool_use", "tool_calls", "tool_result", "tool_call_id")

# The one legitimate site, if Python ever needs one again. Empty on purpose: the
# harness is services/agent/core/stream.ts, and it is not Python.
ALLOWED: frozenset[str] = frozenset()


def _attr_chain(node: ast.AST) -> tuple[str, ...]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return tuple(reversed(parts))


def _calls_a_provider(node: ast.AST) -> bool:
    for inner in ast.walk(node):
        if not isinstance(inner, ast.Call):
            continue
        chain = _attr_chain(inner.func)
        if any(
            chain[-len(tail) :] == tail
            for tail in PROVIDER_CALLS
            if len(chain) >= len(tail)
        ):
            return True
    return False


def _mentions_tools(node: ast.AST) -> bool:
    for inner in ast.walk(node):
        if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
            if any(signal in inner.value for signal in TOOL_SIGNALS):
                return True
        if isinstance(inner, ast.Attribute) and inner.attr in TOOL_SIGNALS:
            return True
        if isinstance(inner, ast.Name) and inner.id in TOOL_SIGNALS:
            return True
    return False


def loops_in(path: Path) -> list[tuple[int, str]]:
    try:
        tree = ast.parse(path.read_text())
    except SyntaxError:
        return []

    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.While, ast.For, ast.AsyncFor)):
            continue
        if _calls_a_provider(node) and _mentions_tools(node):
            found.append(
                (node.lineno, "a provider call and tool-call handling inside one loop")
            )
    return found


def python_files() -> list[Path]:
    files: list[Path] = []
    for top in SCAN:
        for path in (ROOT / top).rglob("*.py"):
            if any(part in SKIP for part in path.parts):
                continue
            files.append(path)
    return sorted(files)


def main() -> int:
    violations: list[str] = []
    for path in python_files():
        rel = str(path.relative_to(ROOT))
        if rel in ALLOWED:
            continue
        for line, why in loops_in(path):
            violations.append(f"{rel}:{line}: {why}")

    if violations:
        print("one-loop gate: a second tool-calling loop appeared in Python\n")
        for violation in violations:
            print(f"  {violation}")
        print(
            "\nThe loop belongs in services/agent/core/stream.ts, which has the budget,"
            "\nthe approval gate, the injection scan and the turn cap already wired."
            "\nIf a Python site is genuinely legitimate, add it to ALLOWED here and say why."
        )
        return 1

    print(f"one-loop gate: 0 tool-calling loops in {len(python_files())} Python files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
