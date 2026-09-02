"""get_technique_graph must look up by child-table technique, not a findings page."""

from unittest.mock import MagicMock

import pytest

from services.api.routers import graph as graph_router

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_technique_graph_queries_child_table(monkeypatch):
    service = MagicMock()
    service.is_using_database.return_value = True
    service.get_findings_by_technique.return_value = []
    monkeypatch.setattr(graph_router, "DatabaseDataService", lambda: service)

    result = await graph_router.get_technique_graph("T1071.001", limit=50)

    service.get_findings_by_technique.assert_called_once_with("T1071.001", limit=50)
    service.get_findings.assert_not_called()
    assert result.metadata["message"] == "No findings with technique T1071.001"


@pytest.mark.asyncio
async def test_technique_graph_falls_back_to_finding_maps_without_a_database(
    monkeypatch,
):
    service = MagicMock()
    service.is_using_database.return_value = False
    service.get_findings.return_value = []
    monkeypatch.setattr(graph_router, "DatabaseDataService", lambda: service)

    await graph_router.get_technique_graph("T1071.001", limit=50)

    service.get_findings.assert_called_once()
    service.get_findings_by_technique.assert_not_called()
