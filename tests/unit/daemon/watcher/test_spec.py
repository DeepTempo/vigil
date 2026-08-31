"""Stage B: WatcherHypothesisSet -> execute_workflow parameters.

The key contracts to hold:
- hypotheses ride the per-run channel (newline-joined);
- techniques / data_domains / scope / narrative are folded into `context`
  (the per-run contract can't carry the first three as fields);
- the finding id is passed so the console's target-context block resolves;
- crucially, the hypotheses we emit must survive execute_workflow's own claim
  gate (_not_a_claim), or a real hunt would be refused before it starts.
"""

import pytest

from core.workflows.workflows_service import _asked_hypotheses, _not_a_claim
from services.daemon.watcher.schemas import WatcherHypothesisSet
from services.daemon.watcher.spec import (
    HUNT_WORKFLOW_ID,
    build_hunt_parameters,
)

pytestmark = pytest.mark.unit


def _hypothesis_set(**overrides):
    data = {
        "hypotheses": [
            "Host WIN-ABC is beaconing to external C2 at 115.238.245.8 over DNS",
            "The svc-backup account is being used for lateral movement to DC-1",
        ],
        "narrative": "WIN-ABC made periodic DNS lookups to a VT-flagged IP.",
        "attack_techniques": ["T1071.004", "T1021"],
        "data_domains": ["dns", "network"],
        "scope": {"hostnames": ["WIN-ABC", "DC-1"], "src_ips": ["10.0.0.5"]},
        "source_finding_id": "splunk-abc123",
    }
    data.update(overrides)
    return WatcherHypothesisSet(**data)


def test_builds_the_expected_parameter_keys():
    params = build_hunt_parameters(_hypothesis_set())
    assert set(params) == {"hypothesis", "finding_id", "context"}
    assert params["finding_id"] == "splunk-abc123"


def test_hypotheses_are_newline_joined_one_per_line():
    params = build_hunt_parameters(_hypothesis_set())
    lines = params["hypothesis"].splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("Host WIN-ABC is beaconing")


def test_context_folds_in_techniques_domains_scope_and_narrative():
    ctx = build_hunt_parameters(_hypothesis_set())["context"]
    assert "T1071.004" in ctx and "T1021" in ctx  # techniques
    assert "dns" in ctx and "network" in ctx  # data domains
    assert "WIN-ABC" in ctx and "10.0.0.5" in ctx  # scope entities
    assert "periodic DNS lookups" in ctx  # narrative


def test_budget_and_iterations_are_optional():
    bare = build_hunt_parameters(_hypothesis_set())
    assert "max_cost_usd" not in bare and "iterations" not in bare

    knobbed = build_hunt_parameters(_hypothesis_set(), max_cost_usd=5.0, iterations=6)
    assert knobbed["max_cost_usd"] == 5.0
    assert knobbed["iterations"] == 6


def test_empty_techniques_and_domains_degrade_gracefully():
    ctx = build_hunt_parameters(
        _hypothesis_set(attack_techniques=[], data_domains=[])
    )["context"]
    assert "none inferred" in ctx
    assert "unspecified" in ctx


def test_emitted_hypotheses_survive_execute_workflow_claim_gate():
    # If any hypothesis fails _not_a_claim, execute_workflow refuses the whole run.
    params = build_hunt_parameters(_hypothesis_set())
    parsed = _asked_hypotheses(params)
    assert parsed, "hypotheses must survive parsing into claims"
    for claim in parsed:
        assert not _not_a_claim(claim), f"would be refused as a non-claim: {claim!r}"


def test_hunt_workflow_id_is_the_shipped_threat_hunt():
    assert HUNT_WORKFLOW_ID == "threat-hunt"
