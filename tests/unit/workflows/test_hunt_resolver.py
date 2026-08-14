# The console's Threat Hunt card now drives the hypothesis loop, which reads a
# different playbook than the compose one: beliefs to test rather than steps.

from __future__ import annotations

import pytest
import yaml

from core.workflows.playbook_resolver import (
    HUNT_CAPABILITIES,
    UnknownPlaybook,
    resolve,
    resolve_hunt,
)

pytestmark = pytest.mark.unit


@pytest.fixture()
def resolved():
    playbook, config = resolve_hunt("threat-hunt")
    return yaml.safe_load(playbook), yaml.safe_load(config)


class TestThePlaybookLayer:
    # The premise is something a person wrote in the definition, not something a
    # model inferred from a prompt -- which is what the null hypothesis guards.
    def test_carries_the_hypotheses_the_definition_states(self, resolved):
        playbook, _ = resolved
        stated = playbook["hypotheses"]
        assert stated
        assert all(isinstance(one, str) and one.strip() for one in stated)

    def test_carries_the_sections_the_hunt_owns(self, resolved):
        playbook, _ = resolved
        for section in ("hypotheses", "attack_techniques", "data_domains"):
            assert section in playbook, f"the arch owns {section} and reads nothing"

    # phases belong to the other loop. A hunt decides what to do next from what
    # the evidence did to each belief, so a step order would say nothing.
    def test_states_no_phases(self, resolved):
        playbook, _ = resolved
        assert "phases" not in playbook


class TestTheConfigLayer:
    def test_binds_the_capabilities_the_arch_asks_for(self, resolved):
        _, config = resolved
        tools = config["tools"]
        provided = {one.get("provides") for one in tools if one.get("provides")}
        # Only what this deployment carries: one it has no tool for is dropped,
        # which is the point of binding rather than naming.
        assert provided
        assert provided <= set(HUNT_CAPABILITIES)

    # Local, because the answer is the run's own ledger. Declared remote it posts
    # to a backend that has never seen it and comes back "no such tool".
    def test_declares_expand_as_local(self, resolved):
        _, config = resolved
        expand = next(tool for tool in config["tools"] if tool["id"] == "expand")
        assert expand["kind"] == "local"

    def test_puts_the_null_hypothesis_on_the_board(self, resolved):
        _, config = resolved
        assert config["hypothesis_loop"] is True


class TestRefusals:
    # A hunt has no phases, so the compose guard would refuse every one of them
    # before the resolver was ever reached.
    def test_a_hunt_is_refused_for_nothing_to_test_not_for_no_phases(self):
        from core.workflows.workflows_service import (WorkflowDefinition,
                                                      _nothing_to_run)

        def _hunt(**extra):
            return WorkflowDefinition(
                workflow_id="h",
                metadata={"run_kind": "hunt", **extra},
                body="",
                file_path="",
            )

        assert _nothing_to_run(_hunt(hypotheses=["something to test"])) == ""
        assert _nothing_to_run(_hunt()) == "hypotheses"

    # Refused rather than run: a hunt with nothing to test opens a ledger, spends
    # a lead turn and concludes having tested nothing.
    def test_refuses_a_definition_with_nothing_to_test(self, monkeypatch):
        import core.workflows.workflows_service as service

        class _Empty:
            metadata: dict = {}
            name = "x"
            description = ""
            use_case = ""
            trigger_examples: list = []
            body = ""

        monkeypatch.setattr(
            service.get_workflows_service(), "get_workflow", lambda _id: _Empty()
        )
        with pytest.raises(UnknownPlaybook, match="no hypotheses"):
            resolve_hunt("threat-hunt")

    def test_refuses_a_workflow_that_does_not_exist(self):
        with pytest.raises(UnknownPlaybook):
            resolve_hunt("no-such-workflow")


# The other four definitions are untouched: they still resolve to phases.
def test_a_compose_definition_still_resolves_to_phases():
    playbook, _ = resolve("incident-response")
    assert yaml.safe_load(playbook)["phases"]
