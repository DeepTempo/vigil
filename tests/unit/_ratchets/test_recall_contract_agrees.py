"""The recall contract is declared twice and must say the same thing.

#729 pins two contracts between the Python domain and the harness: what a read
of episodic memory returns, and the signature of the tool that performs one. A
mismatch fails as "no history" — indistinguishable from an entity nobody has
looked at, which is the same shape as every other silent failure in this area.

There is no runtime seam to catch it either. Nothing calls either half yet: the
rows are #731, the tool is #732, the event is the harness's. By the time a call
exists, three slices will have been written against one of the two
declarations. So the agreement is enforced here, statically, in the window where
both halves are still only text.

Field *order* is not checked. It is a struct on one side and a tuple on the
other, and neither reads by position.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from core.memory import recall_contract as py
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


# A `const X = [...] as const` union. The declared string literals, in order.
def ts_union(body: str, name: str) -> tuple[str, ...]:
    match = re.search(rf"{name}\s*=\s*\[([^\]]*)\]\s*as const", body)
    assert match, f"{name} not found in {TYPESCRIPT}"
    return tuple(re.findall(r'"([^"]+)"', match.group(1)))


# The `readonly` property names of one interface, including those it extends.
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
    match = re.search(rf"{name}\s*=\s*\"([^\"]*)\"\s*;", body)
    assert match, f"const {name} not found in {TYPESCRIPT}"
    return match.group(1)


def entries(body: str) -> list[str]:
    return [entry.strip() for entry in body.split(",") if entry.strip()]


# Vocabularies whose values reach the wire in both directions. A value present on
# one side only is a row one side can write and the other cannot read.
CLOSED_SETS = (
    "TRUST_LEVELS",
    "STANCES",
    "INVESTIGATION_KINDS",
    "VERDICT_OUTCOMES",
    "WINDOW_SOURCES",
    "GAP_DISPOSITIONS",
    "KEY_CASE_SENSITIVE_TYPES",
    "RECALL_RESULT_KEYS",
)

# Declared in TypeScript but owned elsewhere, so there is no Python twin in this
# module to compare against. Each needs a test of its own below, and the coverage
# test at the bottom refuses a name added here without one.
OWNED_ELSEWHERE = {
    "SOURCE_TIERS": "core.memory.source_tier.SourceTier (#728)",
}

# Python holds field names because it builds the mappings; TypeScript holds
# interfaces because it reads them out of a journaled event.
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


@pytest.mark.parametrize("name", CLOSED_SETS)
def test_the_closed_sets_hold_the_same_values(ts: str, name: str):
    assert ts_union(ts, name) == getattr(py, name), (
        f"{name} differs between core/memory/recall_contract.py and "
        f"{TYPESCRIPT.name}. A value one side accepts and the other refuses is a "
        "row that reads as absent rather than as an error."
    )


def test_source_tier_is_not_restated_but_deferred_to(ts: str):
    # #728 owns this vocabulary. The contract restating it would give the tier map
    # and the wire two places to disagree about what a tier is.
    assert ts_union(ts, "SOURCE_TIERS") == tuple(tier.value for tier in SourceTier), (
        "SOURCE_TIERS in the contract has drifted from core/memory/source_tier.py. "
        "The tier map is the owner; the contract follows it."
    )


@pytest.mark.parametrize("fields,interface", ROW_SHAPES.items())
def test_every_row_shape_agrees(ts: str, fields: str, interface: str):
    assert ts_fields(ts, interface) == frozenset(getattr(py, fields)), (
        f"{fields} and interface {interface} name different fields. Whichever "
        "side is missing one reads it as absent, and an absent field in a Verdict "
        "is a conclusion nobody can see."
    )


def test_the_required_argument_is_the_only_one_not_optional(ts: str):
    # Optional on one side and required on the other is a call that succeeds in
    # testing and answers invalid_args in production.
    body = re.search(r"interface RecallArgs\s*\{(.*?)^\}", ts, re.S | re.M)
    assert body, f"interface RecallArgs not found in {TYPESCRIPT}"
    required = frozenset(re.findall(r"^\s*readonly (\w+):", body.group(1), re.M))
    assert required == frozenset(py.RECALL_REQUIRED_ARGS), (
        "the tool's required arguments differ. An argument required on one side "
        "only is a call one side will refuse and the other will happily make."
    )


def test_every_argument_has_a_declared_type():
    # A name agreed without a type is half a signature, and the half that is left
    # is the half nobody disagrees about.
    assert frozenset(py.RECALL_ARG_TYPES) == frozenset(py.RECALL_ARGS), (
        "RECALL_ARG_TYPES and RECALL_ARGS name different arguments; every "
        "argument the tool accepts needs its type stated."
    )


# The two names a grant is written against. A capability spelled differently on
# the two sides binds to nothing, and `providersOf` in core/spec.ts drops what
# nothing provides rather than failing — so the role silently loses the tool.
#
# The caps are not checked, because TypeScript does not declare them. Python owns
# them and copies them into every result; a second declaration to hold them would
# be the reference the contract exists to avoid.
def test_the_tool_and_capability_names_agree(ts: str):
    assert ts_const(ts, "RECALL_TOOL") == py.RECALL_TOOL
    assert ts_const(ts, "RECALL_CAPABILITY") == py.RECALL_CAPABILITY


def test_the_role_grants_agree(ts: str):
    match = re.search(r"RECALL_GRANTS = \{(.*?)\} as const", ts, re.S)
    assert match, f"RECALL_GRANTS not found in {TYPESCRIPT}"
    # The capability arrives as the RECALL_CAPABILITY identifier rather than a
    # literal, which is the point of it being a constant.
    names = {"RECALL_CAPABILITY": ts_const(ts, "RECALL_CAPABILITY")}
    granted = {
        role: tuple(
            names.get(entry, entry.strip('"')) for entry in entries(capabilities)
        )
        for role, capabilities in re.findall(r"(\w+):\s*\[([^\]]*)\]", match.group(1))
    }
    assert granted == dict(py.RECALL_GRANTS), (
        "the role grants differ. A role granted on one side only either calls a "
        "tool it was never meant to hold, or silently holds none."
    )


def test_every_granted_role_is_a_role_the_arch_declares():
    # A grant on a role that does not exist is not a grant. `providersOf` binds by
    # role name, so a misspelling is a capability nothing asks for — dropped
    # silently, because a deployment missing a tool is a supported state.
    arch = ARCH.read_text()
    declared = frozenset(re.findall(r"^ {2,4}(\w+):$", arch, re.M))
    missing = frozenset(py.RECALL_GRANTS) - declared
    assert not missing, (
        "RECALL_GRANTS names roles that services/agent/arch/threathunt.yaml does "
        "not declare:\n  " + "\n  ".join(sorted(missing))
    )


def test_key_normalisation_defers_to_the_extractor():
    # The rule lives in the extractor and Python has to reproduce it. Folding an
    # ARN or an AWS key id makes two different principals one key, and the join
    # still returns rows — just the wrong ones.
    match = re.search(r"CASE_SENSITIVE = new Set\(\[([^\]]*)\]\)", ENTITIES.read_text())
    assert match, f"CASE_SENSITIVE not found in {ENTITIES}"
    assert (
        tuple(re.findall(r'"([^"]+)"', match.group(1))) == py.KEY_CASE_SENSITIVE_TYPES
    ), (
        "KEY_CASE_SENSITIVE_TYPES has drifted from `CASE_SENSITIVE` in "
        f"{ENTITIES.relative_to(REPO_ROOT)}. The extractor owns the rule."
    )


def test_every_declared_vocabulary_is_ratcheted(ts: str):
    # The one way this ratchet can fail to fail: a closed set or interface added
    # to both halves and forgotten here passes by never being compared. The
    # sibling test_run_kinds_agree.py keeps its exclusion list honest the same way.
    unions = frozenset(re.findall(r"export const (\w+) = \[[^\]]*\] as const", ts))
    unratcheted = unions - frozenset(CLOSED_SETS) - frozenset(OWNED_ELSEWHERE)
    assert not unratcheted, (
        "these closed sets are declared in the contract and compared by nothing. "
        "Add each to CLOSED_SETS, or to OWNED_ELSEWHERE with the owner and a test "
        "of its own:\n  " + "\n  ".join(sorted(unratcheted))
    )

    interfaces = frozenset(re.findall(r"export interface (\w+)", ts))
    # Provenance is compared through the rows that extend it, not on its own.
    unshaped = interfaces - frozenset(ROW_SHAPES.values()) - {"RecalledProvenance"}
    assert not unshaped, (
        "these row shapes are declared in the contract and compared by nothing. "
        "Add each to ROW_SHAPES:\n  " + "\n  ".join(sorted(unshaped))
    )
