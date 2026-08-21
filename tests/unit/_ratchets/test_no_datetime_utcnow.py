"""Forbid stdlib ``utcnow`` — use ``core.time.utcnow`` instead.

Naive DateTime columns mean the replacement must stay naive; see ``core.time``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGES = ("core", "services", "tools", "scripts")
HELPER = Path("core/time.py")


def _python_files():
    for package in PACKAGES:
        root = REPO_ROOT / package
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            rel = path.relative_to(REPO_ROOT)
            if rel == HELPER:
                continue
            yield rel


def _utcnow_violations(rel_path: Path):
    source = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(rel_path))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "datetime":
            for alias in node.names:
                if alias.name == "utcnow":
                    yield node.lineno, "from datetime import utcnow"
            continue
        if not isinstance(node, ast.Attribute) or node.attr != "utcnow":
            continue
        base = node.value
        # datetime.utcnow (call or SQLAlchemy default=)
        if isinstance(base, ast.Name) and base.id == "datetime":
            yield node.lineno, "datetime.utcnow"
        # datetime.datetime.utcnow
        elif (
            isinstance(base, ast.Attribute)
            and base.attr == "datetime"
            and isinstance(base.value, ast.Name)
            and base.value.id == "datetime"
        ):
            yield node.lineno, "datetime.datetime.utcnow"


@pytest.mark.unit
def test_no_datetime_utcnow():
    violations = [
        f"{rel}:{lineno}: {kind}"
        for rel in _python_files()
        for lineno, kind in _utcnow_violations(rel)
    ]
    assert not violations, (
        "Deprecated utcnow() found. Use core.time.utcnow() "
        "(naive UTC, matching naive DateTime columns).\n" + "\n".join(violations)
    )


@pytest.mark.unit
def test_no_asyncio_get_event_loop():
    violations = []
    for rel in _python_files():
        source = (REPO_ROOT / rel).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(rel))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "get_event_loop"
                and isinstance(func.value, ast.Name)
                and func.value.id == "asyncio"
            ):
                violations.append(f"{rel}:{node.lineno}: asyncio.get_event_loop()")
    assert not violations, (
        "asyncio.get_event_loop() is deprecated in 3.10+. "
        "Use asyncio.get_running_loop() inside a running event loop.\n"
        + "\n".join(violations)
    )
