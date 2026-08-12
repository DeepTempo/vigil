"""Unit tests for file-based workflow discovery.

Ensures that new workflows added to the workflows/ directory are correctly
parsed and exposed by WorkflowsService.
"""

from core.workflows.workflows_service import WorkflowsService


def test_cloud_incident_workflow_is_discovered():
    """The cloud-incident workflow should load from disk with correct metadata."""
    service = WorkflowsService()

    wf = service.get_workflow("cloud-incident")
    assert wf is not None, "cloud-incident workflow should be discovered"
    assert wf.name == "cloud-incident"
    assert wf.id == "cloud-incident"
    assert "aws" in wf.description.lower() or "azure" in wf.description.lower()

    expected_agents = {
        "investigator",
        "correlator",
        "mitre_analyst",
        "responder",
        "reporter",
    }
    assert expected_agents.issubset(
        set(wf.agents)
    ), f"Expected agents {expected_agents}, got {wf.agents}"

    # Derived from the phases, and only tools a run can actually be granted:
    # create_approval_action is named by the definition but is not a backend
    # tool, so the resolver drops it and asserting it here would guard nothing.
    assert "get_finding" in wf.tools_used
    assert "update_case" in wf.tools_used

    # The cloud-specific guidance is the phases' now, not the body's: the body
    # keeps the overview and each step carries the instructions it is run with.
    guidance = " ".join(p.get("instructions", "") for p in wf.phases).lower()
    assert "control-plane" in guidance or "control plane" in guidance
    assert "cross-account" in guidance or "cross account" in guidance
    assert "blast radius" in guidance


def test_cloud_incident_in_list_workflows():
    """list_workflows should include the cloud-incident definition."""
    service = WorkflowsService()
    workflows = service.list_workflows()
    ids = [w["id"] for w in workflows]
    assert "cloud-incident" in ids

    cloud_wf = next(w for w in workflows if w["id"] == "cloud-incident")
    assert cloud_wf["name"] == "cloud-incident"
    assert "investigator" in cloud_wf["agents"]


def test_cloud_incident_workflow_dict():
    """get_workflow_dict should return serializable metadata and body."""
    service = WorkflowsService()
    d = service.get_workflow_dict("cloud-incident", include_body=True)
    assert d is not None
    assert d["id"] == "cloud-incident"
    assert "body" in d
    assert "cloud" in d["body"].lower()
