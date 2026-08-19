"""Unit tests for starting a workflow on the agent layer (#630).

``execute_workflow`` used to be a loop: it built a composite prompt (or
walked phases) and called ``ClaudeService.chat`` itself. It now enqueues
a compose run and hands back the id, so these lock in what reaches the
queue rather than what reaches a model.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from core.workflows.workflows_service import (WorkflowDefinition,
                                              WorkflowsService)


def _make_workflow(workflow_id: str = "wf-test"):
    return WorkflowDefinition(
        workflow_id=workflow_id,
        file_path=None,
        metadata={
            "name": "Test Workflow",
            "description": "test",
            "use_case": "test",
            "trigger_examples": [],
            "phases": [
                {
                    "id": "triage",
                    "agent": "triage",
                    "name": "Triage",
                    "instructions": "Look at it.",
                }
            ],
        },
        body="An overview.",
        source="file",
    )


@pytest.mark.asyncio
async def test_execute_workflow_enqueues_a_compose_run(monkeypatch):
    monkeypatch.setattr(
        WorkflowsService, "get_workflow", lambda self, wid: _make_workflow(wid)
    )
    captured = {}

    async def _enqueue(job, job_id=None):
        captured["job"] = job
        return "job-1"

    with patch(
        "core.workflows.workflow_run_service.WorkflowRunService.begin_run",
        return_value="run-1",
    ), patch("core.agents.queue.enqueue_run", new=AsyncMock(side_effect=_enqueue)):
        result = await WorkflowsService().execute_workflow(
            "incident-response", {"finding_id": "f-1"}, triggered_by="tester"
        )

    assert result["success"] is True
    assert result["status"] == "queued"
    assert result["run_id"] == "run-1"

    job = captured["job"]
    assert job["run_kind"] == "compose"
    assert job["reason"] == "start"
    assert job["run_id"] == "run-1"


@pytest.mark.asyncio
async def test_the_job_names_the_workflow_rather_than_a_path(monkeypatch):
    """A reference, so an edited definition reaches the next run."""
    monkeypatch.setattr(
        WorkflowsService, "get_workflow", lambda self, wid: _make_workflow(wid)
    )
    captured = {}

    async def _enqueue(job, job_id=None):
        captured["job"] = job
        return "job-1"

    with patch(
        "core.workflows.workflow_run_service.WorkflowRunService.begin_run",
        return_value="run-1",
    ), patch("core.agents.queue.enqueue_run", new=AsyncMock(side_effect=_enqueue)):
        await WorkflowsService().execute_workflow("cloud-incident", {})

    request = captured["job"]["request"]
    assert request["playbook"] == "workflow:cloud-incident"
    assert request["config"] == ""
    assert request["arch"] == ""


@pytest.mark.asyncio
async def test_the_prompt_carries_what_the_run_is_about(monkeypatch):
    monkeypatch.setattr(
        WorkflowsService, "get_workflow", lambda self, wid: _make_workflow(wid)
    )
    captured = {}

    async def _enqueue(job, job_id=None):
        captured["job"] = job
        return "job-1"

    with patch(
        "core.workflows.workflow_run_service.WorkflowRunService.begin_run",
        return_value="run-1",
    ), patch("core.agents.queue.enqueue_run", new=AsyncMock(side_effect=_enqueue)):
        await WorkflowsService().execute_workflow(
            "incident-response", {"context": "a suspicious login"}
        )

    assert "a suspicious login" in captured["job"]["request"]["prompt"]


@pytest.mark.asyncio
async def test_an_unknown_workflow_is_refused_before_the_queue(monkeypatch):
    monkeypatch.setattr(WorkflowsService, "get_workflow", lambda self, wid: None)

    with patch("core.agents.queue.enqueue_run", new=AsyncMock()) as enqueue:
        result = await WorkflowsService().execute_workflow("nope", {})

    assert result["success"] is False
    assert "not found" in result["error"].lower()
    enqueue.assert_not_called()


@pytest.mark.asyncio
async def test_a_queue_outage_fails_the_run_rather_than_leaving_it_running(monkeypatch):
    monkeypatch.setattr(
        WorkflowsService, "get_workflow", lambda self, wid: _make_workflow(wid)
    )

    with patch(
        "core.workflows.workflow_run_service.WorkflowRunService.begin_run",
        return_value="run-1",
    ), patch(
        "core.workflows.workflow_run_service.WorkflowRunService.finalize_run"
    ) as finalize, patch(
        "core.agents.queue.enqueue_run",
        new=AsyncMock(side_effect=RuntimeError("redis is down")),
    ):
        result = await WorkflowsService().execute_workflow("incident-response", {})

    assert result["success"] is False
    finalize.assert_called_once()
    assert finalize.call_args.kwargs["status"] == "failed"
