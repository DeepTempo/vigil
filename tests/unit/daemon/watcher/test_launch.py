"""Stage C: launch a hunt from a hypothesis set, read it back.

Both dependencies are faked — a WorkflowsService that records the call and a
projection reader — so the launch/reconcile wiring is exercised with no live
agent layer, DB, or queue.
"""

import pytest

from services.daemon.watcher.launch import launch_hunt, read_hunt
from services.daemon.watcher.schemas import WatcherHypothesisSet

pytestmark = pytest.mark.unit


class FakeWorkflows:
    """Records execute_workflow's arguments and returns a canned result."""

    def __init__(self, result=None):
        self.result = result or {
            "success": True,
            "status": "queued",
            "run_id": "run-123",
            "job_id": "job-123",
        }
        self.calls = []

    async def execute_workflow(self, workflow_id, parameters, triggered_by=None):
        self.calls.append((workflow_id, parameters, triggered_by))
        return self.result


def _hypothesis_set(**overrides):
    data = {
        "hypotheses": [
            "The internal host 172.16.0.109 is conducting command-and-control "
            "communication with attacker-controlled 45.77.53.176",
        ],
        "narrative": "LogLM flagged C2-tactic traffic to a VT-flagged host.",
        "attack_techniques": [],
        "data_domains": ["network"],
        "scope": {"src_ips": ["172.16.0.109"], "dest_ips": ["45.77.53.176"]},
        "source_finding_id": "f-20260831-abc",
    }
    data.update(overrides)
    return WatcherHypothesisSet(**data)


@pytest.mark.asyncio
async def test_launches_threat_hunt_with_the_built_parameters():
    wf = FakeWorkflows()
    result = await launch_hunt(_hypothesis_set(), workflows=wf)

    assert result["run_id"] == "run-123"
    (workflow_id, params, triggered_by) = wf.calls[0]
    assert workflow_id == "threat-hunt"
    assert set(params) == {"hypothesis", "finding_id", "context"}
    assert "45.77.53.176" in params["hypothesis"]
    assert triggered_by == "watcher"


@pytest.mark.asyncio
async def test_budget_and_iteration_knobs_flow_into_parameters():
    wf = FakeWorkflows()
    await launch_hunt(_hypothesis_set(), workflows=wf, max_cost_usd=5.0, iterations=6)

    (_, params, _) = wf.calls[0]
    assert params["max_cost_usd"] == 5.0
    assert params["iterations"] == 6


@pytest.mark.asyncio
async def test_triggered_by_is_passed_through():
    wf = FakeWorkflows()
    await launch_hunt(_hypothesis_set(), workflows=wf, triggered_by="daemon-sweep")
    assert wf.calls[0][2] == "daemon-sweep"


@pytest.mark.asyncio
async def test_launch_surfaces_a_failed_enqueue():
    wf = FakeWorkflows(result={"success": False, "error": "run queue unavailable"})
    result = await launch_hunt(_hypothesis_set(), workflows=wf)
    assert result["success"] is False
    assert "queue" in result["error"]


@pytest.mark.asyncio
async def test_read_hunt_delegates_to_the_reader():
    projection = {"hypotheses": {"h1": {"status": "active"}}, "evidence": {}}

    async def fake_reader(run_id):
        assert run_id == "run-123"
        return projection

    got = await read_hunt("run-123", reader=fake_reader)
    assert got is projection


@pytest.mark.asyncio
async def test_read_hunt_returns_none_when_not_ready():
    async def fake_reader(run_id):
        return None

    assert await read_hunt("run-123", reader=fake_reader) is None
