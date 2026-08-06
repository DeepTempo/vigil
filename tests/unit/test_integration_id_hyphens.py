"""Regression: Integration IDs for cloud SIEMs must be hyphenated (#555).

Settings persist hyphenated ids (``azure-sentinel``, etc.). Enablement and
config lookups are exact-match, so underscore forms silently never match.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.unit

CANONICAL_IDS = (
    "azure-sentinel",
    "aws-security-hub",
    "microsoft-defender",
)
LEGACY_UNDERSCORE_IDS = (
    "azure_sentinel",
    "aws_security_hub",
    "microsoft_defender",
)

# Call sites that must use Integration IDs (settings keys), not federation
# source names / Redis namespaces / finding source labels.
TARGET_FILES = (
    "daemon/poller.py",
    "services/azure_sentinel_ingestion.py",
    "services/aws_security_hub_ingestion.py",
    "services/microsoft_defender_ingestion.py",
    "tools/microsoft_defender.py",
    "daemon/federation/adapters/azure_sentinel.py",
    "daemon/federation/adapters/aws_security_hub.py",
    "daemon/federation/adapters/microsoft_defender.py",
)

LOOKUP_FUNCS = frozenset({"is_integration_enabled", "get_integration_config"})


def _callee_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _string_const(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _integration_id_literals(path: Path) -> list[tuple[int, str, str]]:
    """Return (lineno, kind, value) for Integration ID string literals."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[tuple[int, str, str]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _callee_name(node.func)
            if name in LOOKUP_FUNCS and node.args:
                value = _string_const(node.args[0])
                if value is not None:
                    found.append((node.lineno, name, value))
            if name == "SIEMIngestionAdapter":
                for kw in node.keywords:
                    if kw.arg == "integration_id":
                        value = _string_const(kw.value)
                        if value is not None:
                            found.append((node.lineno, "integration_id=", value))
    return found


@pytest.mark.parametrize("rel_path", TARGET_FILES)
def test_no_legacy_underscore_integration_ids(rel_path: str):
    literals = _integration_id_literals(REPO_ROOT / rel_path)
    bad = [
        (lineno, kind, value)
        for lineno, kind, value in literals
        if value in LEGACY_UNDERSCORE_IDS
    ]
    assert bad == [], (
        f"{rel_path} still uses underscore Integration IDs "
        f"(expected hyphenated canonical ids): {bad}"
    )


def test_canonical_hyphenated_ids_present_at_call_sites():
    seen: set[str] = set()
    for rel_path in TARGET_FILES:
        for _lineno, _kind, value in _integration_id_literals(REPO_ROOT / rel_path):
            if value in CANONICAL_IDS:
                seen.add(value)
    assert seen == set(CANONICAL_IDS)
