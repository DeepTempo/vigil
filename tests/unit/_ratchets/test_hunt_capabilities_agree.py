# The arch asks for capabilities and Python binds them, so the two lists have to
# name the same things. Duplicated across the language boundary like RUN_KINDS,
# and held to it here rather than discovered when a worker silently loses a tool.

from __future__ import annotations

import re
from pathlib import Path

import pytest

from core.workflows.playbook_resolver import CAPABILITIES, HUNT_CAPABILITIES

pytestmark = pytest.mark.unit

ARCH = Path(__file__).resolve().parents[3] / "services" / "agent" / "arch" / "threathunt.yaml"


def _needs_in_arch() -> set[str]:
    declared: set[str] = set()
    for line in ARCH.read_text().splitlines():
        match = re.match(r"\s*needs:\s*\[(.*)\]\s*$", line)
        if match:
            declared.update(name.strip() for name in match.group(1).split(",") if name.strip())
    return declared


def test_the_arch_declares_needs_at_all():
    # A vacuous pass is the one way this check fails silently.
    assert _needs_in_arch(), "no role in threathunt.yaml declares needs:"


def test_python_binds_every_capability_the_arch_asks_for():
    unbound = _needs_in_arch() - set(HUNT_CAPABILITIES)
    assert not unbound, (
        "threathunt.yaml asks for capabilities the resolver does not emit, so the "
        f"roles needing them would be granted nothing: {sorted(unbound)}"
    )


def test_the_resolver_emits_nothing_the_arch_does_not_ask_for():
    unused = set(HUNT_CAPABILITIES) - _needs_in_arch()
    assert not unused, (
        f"the resolver binds capabilities no role asks for: {sorted(unused)}"
    )


def test_every_capability_names_at_least_one_candidate():
    empty = [name for name in HUNT_CAPABILITIES if not CAPABILITIES.get(name)]
    assert not empty, f"capabilities with no candidate tool: {empty}"
