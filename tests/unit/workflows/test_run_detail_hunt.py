# A hunt writes no phase rows, so the run detail the console expands would say
# "no additional detail" for every hunt. It carries the agent layer's standing instead.

from __future__ import annotations

import pytest

from core.workflows import workflows_router as router

pytestmark = pytest.mark.unit

STANDING = {"status": "active", "iteration": 2, "hypotheses": [], "evidence_count": 0}


@pytest.fixture()
def run_of(monkeypatch):
    import core.workflows.workflow_run_service as runs

    def _for(workflow_id: str):
        class _Runs:
            def get_run(self, run_id):
                return {"run_id": run_id, "workflow_id": workflow_id}

            def list_phases(self, _run_id):
                return []

        monkeypatch.setattr(runs, "get_workflow_run_service", lambda: _Runs())

    return _for


async def _reads(_run_id):
    return STANDING


@pytest.mark.asyncio
async def test_a_hunt_run_carries_the_standing_of_its_hypotheses(run_of, monkeypatch):
    run_of("threat-hunt")
    monkeypatch.setattr(router, "read_projection", _reads)

    detail = await router.get_workflow_run("run-1")

    assert detail["hunt"] == STANDING


# The four compose definitions are untouched, and asking the agent layer about one
# is a round trip whose answer nothing would read.
@pytest.mark.asyncio
async def test_a_compose_run_is_not_asked_about(run_of, monkeypatch):
    run_of("incident-response")
    asked = []

    async def _record(run_id):
        asked.append(run_id)
        return STANDING

    monkeypatch.setattr(router, "read_projection", _record)

    detail = await router.get_workflow_run("run-2")

    assert asked == []
    assert "hunt" not in detail


def test_the_threat_hunt_definition_is_the_one_that_reads_as_a_hunt():
    assert router._is_hunt("threat-hunt")
    assert not router._is_hunt("incident-response")
    assert not router._is_hunt(None)
