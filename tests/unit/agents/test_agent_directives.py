"""The directive envelope Python writes is the one TypeScript reads back (GH #646)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO))

from core.agents.directives import (  # noqa: E402
    DIRECTIVE_KINDS,
    InvalidDirective,
    build_directive,
)

pytestmark = pytest.mark.unit


def test_carries_the_envelope_the_drain_reads():
    directive = build_directive(
        "note", "the 03:00 spike is our backup window", "analyst@example.com"
    )

    # Every field the TypeScript Directive requires, and origin marking it as an
    # operator's rather than the controller's own voice.
    assert set(directive) == {
        "directive_id",
        "actor",
        "kind",
        "text",
        "created_at",
        "origin",
    }
    assert directive["directive_id"].startswith("dir-")
    assert directive["origin"] == "inbox"
    assert directive["actor"] == "analyst@example.com"


def test_refuses_a_kind_the_drain_could_not_apply():
    with pytest.raises(InvalidDirective, match="unknown directive kind aprove"):
        build_directive("aprove", "looks right", "analyst")


def test_refuses_a_directive_nobody_owns():
    # The ledger's job is to say who steered a run; an unattributed directive
    # defeats that, so it is refused here rather than journaled.
    with pytest.raises(InvalidDirective, match="needs an actor"):
        build_directive("note", "someone said something", "")


def test_refuses_a_field_the_workflow_never_reads():
    with pytest.raises(InvalidDirective, match="unknown directive fields: checkpoint"):
        build_directive("approve", "yes", "analyst", {"checkpoint": "chk-1"})


def test_carries_the_fields_a_workflow_owns():
    directive = build_directive(
        "approve", "reviewed", "analyst", {"checkpoint_id": "chk-h1"}
    )
    assert directive["checkpoint_id"] == "chk-h1"


def test_kinds_match_the_typescript_vocabulary():
    """DIRECTIVE_KINDS is declared in two languages, so drift is the failure mode."""
    declared = (
        REPO / "services" / "agent" / "workflows" / "hunt" / "types.ts"
    ).read_text()
    block = declared.split("export const DIRECTIVE_KINDS = [")[1].split("]")[0]
    assert sorted(DIRECTIVE_KINDS) == sorted(
        line.strip().strip(',"') for line in block.strip().splitlines()
    )
