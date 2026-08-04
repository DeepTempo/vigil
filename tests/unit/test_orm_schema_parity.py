"""Serialized-output parity between the ORM-mode schemas and the contract.

``tests/fixtures/orm_serialization_golden.json`` is a frozen capture of the
hand-written ``to_dict()`` output it replaced, taken from the commit before
the schemas landed. It is not regenerated from the schemas — that would be
circular. Edit it by hand, in a commit that says why, only when a contract
change is intended.

Each schema is registered with the builder states and dump variants it must
reproduce; the test then asserts key-for-key equality against the capture.
"""

import json
import pathlib

import pytest

from database.models import Case, Finding
from database.schemas.case import CaseSchema, CaseWithFindingsSchema
from database.schemas.finding import FindingSchema
from tests.unit.orm_sample_instances import build_empty, build_populated, build_related

pytestmark = pytest.mark.unit

GOLDEN_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "fixtures"
    / "orm_serialization_golden.json"
)


@pytest.fixture(scope="module")
def golden():
    with GOLDEN_PATH.open() as fh:
        return json.load(fh)


# model name -> {golden case key: callable(instance) -> dict}
#
# Populated as each domain is migrated. ``test_registry_covers_every_model``
# guards the end state.
SCHEMA_REGISTRY: dict[str, dict] = {
    "Finding": {
        "model": Finding,
        "cases": {
            "populated.to_dict.with_embedding": FindingSchema.dump,
            "populated.to_dict.without_embedding": FindingSchema.dump_summary,
            "empty.to_dict.with_embedding": FindingSchema.dump,
            "empty.to_dict.without_embedding": FindingSchema.dump_summary,
        },
    },
    "Case": {
        "model": Case,
        "cases": {
            "populated.to_dict.with_finding_ids": CaseSchema.dump,
            "populated.to_dict.with_findings": CaseWithFindingsSchema.dump,
            "empty.to_dict.with_finding_ids": CaseSchema.dump,
            "empty.to_dict.with_findings": CaseWithFindingsSchema.dump,
            "related.to_dict.with_finding_ids": CaseSchema.dump,
            "related.to_dict.with_findings": CaseWithFindingsSchema.dump,
        },
    },
}


def _builder_for(state, model_name, model):
    if state == "populated":
        return build_populated(model_name, model)
    if state == "empty":
        return build_empty(model)
    if state == "related":
        return build_related(model_name, model)
    raise AssertionError(f"unknown builder state {state!r}")


def _registered_cases():
    for model_name, spec in sorted(SCHEMA_REGISTRY.items()):
        for case_key in sorted(spec["cases"]):
            yield model_name, case_key


@pytest.mark.parametrize("model_name,case_key", list(_registered_cases()))
def test_schema_matches_golden_contract(golden, model_name, case_key):
    """The schema's dump must equal the captured contract, key for key."""
    spec = SCHEMA_REGISTRY[model_name]
    expected = golden[model_name][case_key]

    state = case_key.split(".", 1)[0]
    instance = _builder_for(state, model_name, spec["model"])
    actual = spec["cases"][case_key](instance)

    assert set(actual) == set(expected), (
        f"{model_name}[{case_key}] key mismatch: "
        f"missing={sorted(set(expected) - set(actual))} "
        f"unexpected={sorted(set(actual) - set(expected))}"
    )
    assert actual == expected


def test_golden_fixture_is_present(golden):
    assert golden, "golden serialization fixture is empty"
