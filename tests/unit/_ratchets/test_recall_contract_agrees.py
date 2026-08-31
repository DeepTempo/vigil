"""The recall contract is declared twice and must say the same thing.

A mismatch fails as "no history" — indistinguishable from an entity nobody has
looked at. Nothing calls either half yet (rows are #731, the tool #732, the
event the harness's), so by the time a call exists three slices will have been
written against one of the two declarations. The agreement is enforced here,
statically, while both halves are still only text.

Field order is not checked: it is a struct on one side and a tuple on the other,
and neither reads by position.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from core.memory import recall_contract as py
from core.memory.source_tier import InvestigationKind as SourceNamingKind
from core.memory.source_tier import SourceTier

REPO_ROOT = Path(__file__).resolve().parents[3]
AGENT = REPO_ROOT / "services" / "agent"
TYPESCRIPT = AGENT / "contracts" / "memory.ts"
ARCH = AGENT / "arch" / "threathunt.yaml"
ENTITIES = AGENT / "workflows" / "hunt" / "entities.ts"

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def ts() -> str:
    return TYPESCRIPT.read_text()


def ts_union(body: str, name: str) -> tuple[str, ...]:
    match = re.search(rf"{name}\s*=\s*\[([^\]]*)\]\s*as const", body)
    assert match, f"{name} not found in {TYPESCRIPT}"
    return tuple(re.findall(r'"([^"]+)"', match.group(1)))


# Property names of one interface, including those it extends.
def ts_fields(body: str, name: str) -> frozenset[str]:
    match = re.search(
        rf"interface {name}(?: extends ([A-Za-z]+))?\s*\{{(.*?)^\}}", body, re.S | re.M
    )
    assert match, f"interface {name} not found in {TYPESCRIPT}"
    inherited = ts_fields(body, match.group(1)) if match.group(1) else frozenset()
    return inherited | frozenset(
        re.findall(r"^\s*readonly (\w+)\??:", match.group(2), re.M)
    )


def ts_const(body: str, name: str) -> str:
    match = re.search(rf'{name}\s*=\s*"([^"]*)"\s*;', body)
    assert match, f"const {name} not found in {TYPESCRIPT}"
    return match.group(1)


def values(vocabulary) -> tuple[str, ...]:
    return tuple(member.value for member in vocabulary)


# TypeScript declares a vocabulary as an `as const` array; Python declares one as
# an Enum where callers hold a value, and as a tuple where it is only a wire key.
ENUMS = {
    "TRUST_LEVELS": py.Trust,
    "STANCES": py.Stance,
    "INVESTIGATION_KINDS": py.InvestigationKind,
    "VERDICT_OUTCOMES": py.VerdictOutcome,
    "WINDOW_SOURCES": py.WindowSource,
    "GAP_DISPOSITIONS": py.GapDisposition,
}

TUPLES = ("KEY_CASE_SENSITIVE_TYPES", "RECALL_RESULT_KEYS", "RECALL_KEY_ARGS")

# Declared in TypeScript but owned by another module, so each needs an owner test
# below rather than a twin here.
OWNED_ELSEWHERE = {"SOURCE_TIERS": "core.memory.source_tier.SourceTier (#728)"}

ROW_SHAPES = {
    "SIGHTING_FIELDS": "RecalledSighting",
    "VERDICT_FIELDS": "RecalledVerdict",
    "VERDICT_SOURCE_FIELDS": "RecalledVerdictSource",
    "GAP_FIELDS": "RecalledGap",
    "WINDOW_FIELDS": "ActivityWindow",
    "RECALL_RESULT_KEYS": "RecallResult",
    "RECALL_ARGS": "RecallArgs",
    "DROPPED_KINDS": "RecallDropped",
    "DROPPED_REASONS": "DroppedRows",
    "RANKING_KEYS": "RecallRanking",
}

DRIFT = (
    "A value one side accepts and the other refuses is a row that reads as "
    "absent rather than as an error."
)


@pytest.mark.parametrize("name,vocabulary", ENUMS.items())
def test_the_enum_vocabularies_hold_the_same_values(ts: str, name: str, vocabulary):
    assert ts_union(ts, name) == values(vocabulary), f"{name} differs. {DRIFT}"


@pytest.mark.parametrize("name", TUPLES)
def test_the_wire_key_vocabularies_hold_the_same_values(ts: str, name: str):
    assert ts_union(ts, name) == getattr(py, name), f"{name} differs. {DRIFT}"


def test_source_tier_is_followed_not_restated(ts: str):
    assert ts_union(ts, "SOURCE_TIERS") == values(
        SourceTier
    ), "SOURCE_TIERS has drifted from core/memory/source_tier.py, which owns it."


def test_investigation_kinds_extend_the_source_naming_ones():
    # source_tier's enum selects a source vocabulary and covers only the kinds
    # that name sources. Ours is the domain vocabulary and must contain it, or
    # the tier map cannot grade a row this contract can carry.
    extra = set(values(py.InvestigationKind)) - set(values(SourceNamingKind))
    assert extra == {"analyst"}, (
        "InvestigationKind must extend core/memory/source_tier.py's by exactly "
        f"`analyst`, the kind that names no sources; it adds {sorted(extra)}."
    )


@pytest.mark.parametrize("fields,interface", ROW_SHAPES.items())
def test_every_row_shape_agrees(ts: str, fields: str, interface: str):
    assert ts_fields(ts, interface) == frozenset(getattr(py, fields)), (
        f"{fields} and interface {interface} name different fields. An absent "
        "field in a Verdict is a conclusion nobody can see."
    )


def test_no_argument_is_required_and_the_key_invariant_stands(ts: str):
    # Requiring `entity_keys` would make the singular unusable, which is the one
    # call it exists for. "At least one key argument" is data, not a type.
    body = re.search(r"interface RecallArgs\s*\{(.*?)^\}", ts, re.S | re.M)
    assert body, f"interface RecallArgs not found in {TYPESCRIPT}"
    required = frozenset(re.findall(r"^\s*readonly (\w+):", body.group(1), re.M))
    assert not required, (
        "these RecallArgs are required, which makes the singular entity_key "
        "unusable:\n  " + "\n  ".join(sorted(required))
    )
    assert py.RECALL_KEY_ARGS, "RECALL_KEY_ARGS must name the keys a call needs"
    assert frozenset(py.RECALL_KEY_ARGS) <= frozenset(
        py.RECALL_ARGS
    ), "RECALL_KEY_ARGS names arguments the tool does not accept"


def test_every_argument_is_declared_in_the_registrable_schema():
    # RECALL_ARGS derives from the schema, so this catches a name added to one of
    # the wire halves and not the other via the row-shape test above.
    assert py.RECALL_ARGS == tuple(py.RECALL_PARAMETERS["properties"])
    assert (
        py.RECALL_PARAMETERS["required"] == []
    ), "the schema must require nothing; the key invariant is RECALL_KEY_ARGS"


def test_the_tool_and_capability_names_agree(ts: str):
    # A capability spelled differently binds to nothing, and `providersOf` drops
    # what nothing provides rather than failing, so the role silently loses it.
    assert ts_const(ts, "RECALL_TOOL") == py.RECALL_TOOL
    assert ts_const(ts, "RECALL_CAPABILITY") == py.RECALL_CAPABILITY


def test_the_role_grants_agree(ts: str):
    match = re.search(r"RECALL_GRANTS = \{(.*?)\} as const", ts, re.S)
    assert match, f"RECALL_GRANTS not found in {TYPESCRIPT}"
    # The capability arrives as an identifier, which is the point of the constant.
    names = {"RECALL_CAPABILITY": ts_const(ts, "RECALL_CAPABILITY")}
    granted = {
        role: tuple(
            names.get(entry.strip(), entry.strip().strip('"'))
            for entry in capabilities.split(",")
            if entry.strip()
        )
        for role, capabilities in re.findall(r"(\w+):\s*\[([^\]]*)\]", match.group(1))
    }
    assert granted == dict(py.RECALL_GRANTS), (
        "the role grants differ. A role granted on one side only either calls a "
        "tool it was never meant to hold, or silently holds none."
    )


def test_every_granted_role_is_a_role_the_arch_declares():
    declared = frozenset(re.findall(r"^ {2,4}(\w+):$", ARCH.read_text(), re.M))
    missing = frozenset(py.RECALL_GRANTS) - declared
    assert not missing, (
        "RECALL_GRANTS names roles threathunt.yaml does not declare, and a grant "
        "on a role that does not exist is dropped silently:\n  "
        + "\n  ".join(sorted(missing))
    )


def test_key_normalisation_defers_to_the_extractor():
    match = re.search(r"CASE_SENSITIVE = new Set\(\[([^\]]*)\]\)", ENTITIES.read_text())
    assert match, f"CASE_SENSITIVE not found in {ENTITIES}"
    declared = tuple(re.findall(r'"([^"]+)"', match.group(1)))
    assert declared == py.KEY_CASE_SENSITIVE_TYPES, (
        "KEY_CASE_SENSITIVE_TYPES has drifted from CASE_SENSITIVE in "
        f"{ENTITIES.relative_to(REPO_ROOT)}, which owns the rule. Folding an ARN "
        "returns rows, just the wrong ones."
    )


def test_every_declared_vocabulary_is_ratcheted(ts: str):
    # The one way this ratchet could stop being able to fail: something added to
    # both halves and compared by neither.
    unions = frozenset(re.findall(r"export const (\w+) = \[[^\]]*\] as const", ts))
    unratcheted = (
        unions - frozenset(ENUMS) - frozenset(TUPLES) - frozenset(OWNED_ELSEWHERE)
    )
    assert not unratcheted, (
        "these vocabularies are declared and compared by nothing. Add each to "
        "ENUMS or TUPLES, or to OWNED_ELSEWHERE with an owner test:\n  "
        + "\n  ".join(sorted(unratcheted))
    )

    interfaces = frozenset(re.findall(r"export interface (\w+)", ts))
    # Provenance is compared through the rows that extend it.
    unshaped = interfaces - frozenset(ROW_SHAPES.values()) - {"RecalledProvenance"}
    assert not unshaped, (
        "these row shapes are declared and compared by nothing. Add each to "
        "ROW_SHAPES:\n  " + "\n  ".join(sorted(unshaped))
    )
