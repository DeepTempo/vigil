"""Splunk enrich_case must append a notes entry, not assign a markdown string."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.integrations.splunk.enrichment import SplunkEnrichmentService

pytestmark = pytest.mark.unit


def _service():
    svc = SplunkEnrichmentService.__new__(SplunkEnrichmentService)
    svc.splunk_service = MagicMock()
    svc.claude_service = MagicMock()
    svc.data_service = MagicMock()
    svc.extract_indicators = MagicMock(
        return_value={
            "ips": [],
            "domains": [],
            "hashes": [],
            "usernames": [],
            "hostnames": [],
        }
    )
    svc.query_splunk_for_indicators = MagicMock(
        return_value={"summary": {"total_events": 4}}
    )
    svc.analyze_with_claude = MagicMock(return_value="ai analysis")
    return svc


def test_enrich_case_appends_note_and_keeps_existing():
    svc = _service()
    prior = {"timestamp": "2026-01-01T00:00:00Z", "content": "analyst note"}
    svc.data_service.get_case.return_value = {
        "case_id": "c1",
        "finding_ids": [],
        "notes": [prior],
    }

    result = svc.enrich_case("c1")

    assert result["success"] is True
    svc.data_service.update_case.assert_called_once()
    notes = svc.data_service.update_case.call_args.kwargs["notes"]
    assert notes[0] == prior
    assert "Splunk Enrichment" in notes[1]["content"]
    assert "ai analysis" in notes[1]["content"]
    assert notes[1]["timestamp"].endswith("Z")
    assert set(notes[1]) == {"timestamp", "content"}


def test_enrich_case_does_not_pass_a_string_as_notes():
    """The pre-#718 writer assigned the markdown blob; MutableList refuses that."""
    svc = _service()
    svc.data_service.get_case.return_value = {
        "case_id": "c1",
        "finding_ids": [],
        "notes": [],
    }

    def _reject_string(case_id, **updates):
        if isinstance(updates.get("notes"), str):
            raise ValueError(
                "Attribute 'notes' does not accept objects of type <class 'str'>"
            )
        return True

    svc.data_service.update_case.side_effect = _reject_string

    result = svc.enrich_case("c1")

    assert result["success"] is True
    notes = svc.data_service.update_case.call_args.kwargs["notes"]
    assert isinstance(notes, list)
    assert len(notes) == 1
