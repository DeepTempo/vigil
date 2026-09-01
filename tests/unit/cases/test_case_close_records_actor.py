"""Every path that closes a Case records who closed it and why (#733).

This is the premise the whole of #733 rests on. Analysts do not close Cases
through ``POST /cases/{id}/close``; they PATCH ``status`` to ``closed`` from the
console, which recorded neither a category nor an actor. Episodic memory reads
Trust ``analyst`` off that record, so without it the highest-value thing the
system produces -- a person looked and said no -- reached memory as nothing.

Asserted at each writer rather than through the Distil, because what is wrong
when this breaks is the close, not the mapping.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.cases.closure import ClosedByKind, ClosureCategory

pytestmark = pytest.mark.unit

ANALYST = SimpleNamespace(username="nestor")


class _Session:
    """Enough session for the router: what it looked up, and what it added."""

    def __init__(self, existing=None):
        self._existing = existing
        self.added = []

    def get(self, _model, _pk):
        return self._existing

    def add(self, row):
        self.added.append(row)


def _routes(monkeypatch, *, case, updated=True):
    from services.api.routers import cases

    captured = {}

    def _update(case_id, **updates):
        captured["updates"] = updates
        return updated

    monkeypatch.setattr(cases.data_service, "get_case", lambda case_id: case)
    monkeypatch.setattr(cases.data_service, "update_case", _update)
    return cases, captured


@pytest.mark.asyncio
async def test_a_status_edit_to_closed_records_the_principal(monkeypatch):
    from services.api.routers.cases import CaseUpdate

    cases, _ = _routes(monkeypatch, case={"case_id": "c1", "status": "investigating"})
    session = _Session()

    await cases.update_case("c1", CaseUpdate(status="closed"), session, ANALYST)

    (closure,) = session.added
    assert closure.case_id == "c1"
    # The name comes from the authenticated principal, never from the body:
    # a client-supplied one would let any caller claim an analyst concluded.
    assert closure.closed_by == "nestor"
    assert closure.closed_by_kind == ClosedByKind.ANALYST.value
    assert closure.closure_category == ClosureCategory.UNSPECIFIED.value
    assert closure.closed_at is not None


@pytest.mark.asyncio
async def test_it_does_not_invent_a_determination(monkeypatch):
    from services.api.routers.cases import CaseUpdate

    cases, _ = _routes(monkeypatch, case={"case_id": "c1", "status": "open"})
    session = _Session()

    await cases.update_case("c1", CaseUpdate(status="closed"), session, ANALYST)

    (closure,) = session.added
    # `unspecified` is not one of the four determinations. It says the Case
    # closed and no reason was stated, which is what happened.
    assert closure.closure_category not in {
        ClosureCategory.RESOLVED.value,
        ClosureCategory.FALSE_POSITIVE.value,
        ClosureCategory.DUPLICATE.value,
        ClosureCategory.UNABLE_TO_RESOLVE.value,
    }


@pytest.mark.asyncio
async def test_a_status_edit_to_something_else_records_nothing(monkeypatch):
    from services.api.routers.cases import CaseUpdate

    cases, _ = _routes(monkeypatch, case={"case_id": "c1", "status": "open"})
    session = _Session()

    await cases.update_case("c1", CaseUpdate(status="investigating"), session, ANALYST)

    assert session.added == []


@pytest.mark.asyncio
async def test_re_saving_an_already_closed_case_is_an_edit_and_not_a_close(monkeypatch):
    from services.api.routers.cases import CaseUpdate

    cases, _ = _routes(monkeypatch, case={"case_id": "c1", "status": "closed"})
    session = _Session()

    await cases.update_case(
        "c1", CaseUpdate(title="retitled", status="closed"), session, ANALYST
    )

    # Stamping here would move the closure's date and re-derive its Verdict for
    # a change that concluded nothing new.
    assert session.added == []


@pytest.mark.asyncio
async def test_a_real_category_is_never_overwritten(monkeypatch):
    from services.api.routers.cases import CaseUpdate

    cases, _ = _routes(monkeypatch, case={"case_id": "c1", "status": "investigating"})
    session = _Session(existing=SimpleNamespace(case_id="c1"))

    await cases.update_case("c1", CaseUpdate(status="closed"), session, ANALYST)

    assert session.added == []


@pytest.mark.asyncio
async def test_a_failed_update_records_no_close(monkeypatch):
    from fastapi import HTTPException

    from services.api.routers.cases import CaseUpdate

    cases, _ = _routes(
        monkeypatch, case={"case_id": "c1", "status": "open"}, updated=False
    )
    session = _Session()

    with pytest.raises(HTTPException):
        await cases.update_case("c1", CaseUpdate(status="closed"), session, ANALYST)

    assert session.added == []


@pytest.mark.asyncio
async def test_the_close_endpoint_takes_the_principal_and_not_the_body(monkeypatch):
    from services.api.routers import cases
    from services.api.routers.cases import ClosureInfo

    captured = {}

    class _Service:
        def close_case(self, session, case_id, **kwargs):
            captured.update(kwargs)
            captured["case_id"] = case_id
            return MagicMock()

    import core.cases.case_workflow_service as workflow

    monkeypatch.setattr(workflow, "CaseWorkflowService", _Service)
    monkeypatch.setattr(cases.CaseClosureInfoSchema, "dump", staticmethod(lambda r: {}))

    await cases.close_case(
        "c1",
        ClosureInfo(
            closure_category="false_positive",
            false_positive_reason="the scanner is ours",
        ),
        MagicMock(),
        ANALYST,
    )

    assert captured["closed_by"] == "nestor"
    assert captured["closed_by_kind"] is ClosedByKind.ANALYST
    # Named in the rationale fallback and previously not an argument at all, so
    # the dedicated close path could never write the field it fell back to.
    assert captured["false_positive_reason"] == "the scanner is ours"


def test_the_close_request_has_no_closed_by_field():
    from services.api.routers.cases import ClosureInfo

    assert "closed_by" not in ClosureInfo.model_fields
