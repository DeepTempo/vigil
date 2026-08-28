"""ingest_case wraps a string ``notes`` into a one-element list of entries."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.ingestion.ingestion_service import IngestionService

pytestmark = pytest.mark.unit


def _service():
    svc = IngestionService.__new__(IngestionService)
    svc.use_database = True
    svc.db_service = MagicMock()
    svc.db_service.get_case.return_value = None
    svc.db_service.create_case.return_value = object()
    svc.stats = {
        "findings_total": 0,
        "findings_imported": 0,
        "findings_skipped": 0,
        "findings_errors": 0,
        "cases_total": 0,
        "cases_imported": 0,
        "cases_skipped": 0,
        "cases_errors": 0,
    }
    svc._identity_warned = set()
    return svc


def test_ingest_case_wraps_string_notes_into_an_entry():
    svc = _service()

    assert svc.ingest_case({"case_id": "c1", "notes": "imported as text"}) is True

    notes = svc.db_service.create_case.call_args.kwargs["notes"]
    assert isinstance(notes, list)
    assert notes[0]["content"] == "imported as text"
    assert notes[0]["timestamp"].endswith("Z")
    assert set(notes[0]) == {"timestamp", "content"}


def test_ingest_case_passes_list_notes_through():
    svc = _service()
    original = [{"timestamp": "2026-01-01T00:00:00Z", "content": "already a list"}]

    assert svc.ingest_case({"case_id": "c1", "notes": original}) is True

    assert svc.db_service.create_case.call_args.kwargs["notes"] is original


def test_ingest_case_wraps_string_notes_on_json_fallback(monkeypatch):
    svc = IngestionService.__new__(IngestionService)
    svc.use_database = False
    svc.db_service = None
    svc.stats = {
        "findings_total": 0,
        "findings_imported": 0,
        "findings_skipped": 0,
        "findings_errors": 0,
        "cases_total": 0,
        "cases_imported": 0,
        "cases_skipped": 0,
        "cases_errors": 0,
    }
    svc._identity_warned = set()

    stored = []

    class _FakeDataService:
        def get_cases(self):
            return stored

        def save_cases(self, cases):
            stored[:] = list(cases)
            return True

    monkeypatch.setattr(
        "core.storage.database_data_service.DatabaseDataService",
        _FakeDataService,
    )

    incoming = {"case_id": "c1", "notes": "imported as text"}
    assert svc.ingest_case(incoming) is True
    assert incoming["notes"] == "imported as text"
    assert stored[0]["notes"][0]["content"] == "imported as text"
    assert set(stored[0]["notes"][0]) == {"timestamp", "content"}
