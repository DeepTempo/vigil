"""Assignment shape for every column wrapped in ``JSONBList``.

#709 wrapped ``Case.notes`` (and the other JSONB arrays) in
``MutableList.as_mutable(JSONB)`` so in-place appends persist. That wrap
rejects a plain ``str`` with ``ValueError`` rather than coercing it —
which is the contract the writers in #718 have to meet. These tests pin
the assignment path #709 shipped without: a list is accepted on every
wrapped column, and a string on ``Case.notes`` is refused.
"""

from __future__ import annotations

import pytest
from sqlalchemy import inspect as sa_inspect

import core.storage.models as models
from core.storage.models import JSONBList
from tests.unit.storage.orm_sample_instances import iter_serializable_models

pytestmark = pytest.mark.unit


def _jsonb_list_columns():
    """Every mapped column that uses the ``JSONBList`` type object."""
    found = []
    for name, model in iter_serializable_models():
        for column in sa_inspect(model).mapper.columns:
            if column.type is JSONBList:
                found.append((name, model, column.key))
    return found


def test_jsonb_list_discovery_includes_case_notes():
    """The walk must actually see the wrap; an empty list would hide a revert."""
    names = {(name, key) for name, _model, key in _jsonb_list_columns()}
    assert ("Case", "notes") in names
    assert ("Case", "timeline") in names
    assert ("Case", "activities") in names
    assert ("Case", "resolution_steps") in names
    assert ("CaseEvidence", "chain_of_custody") in names


@pytest.mark.parametrize(
    "model_name,key",
    [(name, key) for name, _model, key in _jsonb_list_columns()] or [("Case", "notes")],
)
def test_jsonb_list_column_accepts_a_list(model_name, key):
    model = getattr(models, model_name)
    instance = model()
    setattr(instance, key, [{"ok": True}])
    assert list(getattr(instance, key)) == [{"ok": True}]


def test_assigning_a_string_to_case_notes_raises():
    case = models.Case()
    with pytest.raises(ValueError, match="does not accept objects of type"):
        case.notes = "some note text"
