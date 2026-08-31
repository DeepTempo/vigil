"""Stage A acceptance: the Hypothesizer turns an enriched alert into a valid,
testable hypothesis set — with no real LLM or network.

The model is faked (a gateway that returns canned text), so these tests exercise
the Hypothesizer's own logic: context gathering, prompt construction, reply
parsing, technique merge, and validation.
"""

import json

import pytest

from services.daemon.watcher.hypothesizer import HypothesizerError, form_hypotheses
from services.daemon.watcher.schemas import WatcherHypothesisSet

pytestmark = pytest.mark.unit


class FakeGateway:
    """Records the prompt it was handed and returns a canned reply."""

    def __init__(self, reply):
        self.reply = reply
        self.last_prompt = None

    async def submit_triage(self, prompt):
        self.last_prompt = prompt
        return self.reply


def _botsv3_finding():
    """A BOTSv3-style enriched finding: entities + a source technique + the
    reputation an enrichment pass would have attached."""
    return {
        "finding_id": "splunk-abc123",
        "data_source": "splunk",
        "severity": "high",
        "title": "Suspicious DNS beaconing",
        "description": "Host made periodic DNS lookups to a rare external domain.",
        "entity_context": {
            "src_ips": ["10.0.0.5"],
            "dest_ips": ["115.238.245.8"],
            "hostnames": ["WIN-ABC"],
            "usernames": ["svc-backup"],
        },
        "mitre_predictions": {"T1071.004": 0.8},
        "enrichment": {
            "ip_115.238.245.8": {
                "virustotal": {"malicious": 3, "reputation": -40},
                "shodan": {"org": "EvilCorp", "vulns": ["CVE-2021-1234"]},
            }
        },
    }


def _valid_reply(**overrides):
    payload = {
        "hypotheses": [
            "Host WIN-ABC is beaconing to external C2 at 115.238.245.8 over DNS",
        ],
        "narrative": "WIN-ABC made periodic DNS lookups to a VT-flagged IP.",
        "attack_techniques": ["T1568.002"],
        "data_domains": ["dns", "network"],
    }
    payload.update(overrides)
    return json.dumps(payload)


@pytest.mark.asyncio
async def test_forms_a_valid_hypothesis_set():
    gateway = FakeGateway(_valid_reply())
    result = await form_hypotheses(_botsv3_finding(), gateway=gateway)

    assert isinstance(result, WatcherHypothesisSet)
    assert len(result.hypotheses) >= 1
    assert result.narrative
    assert result.source_finding_id == "splunk-abc123"


@pytest.mark.asyncio
async def test_scope_is_built_deterministically_from_entities():
    gateway = FakeGateway(_valid_reply())
    result = await form_hypotheses(_botsv3_finding(), gateway=gateway)

    assert result.scope["src_ips"] == ["10.0.0.5"]
    assert result.scope["dest_ips"] == ["115.238.245.8"]
    assert result.scope["hostnames"] == ["WIN-ABC"]
    assert result.scope["usernames"] == ["svc-backup"]


@pytest.mark.asyncio
async def test_scope_tolerates_singular_key_variants():
    finding = _botsv3_finding()
    finding["entity_context"] = {"src_ip": "10.0.0.9", "host": "DC-1", "user": "root"}
    gateway = FakeGateway(_valid_reply())

    result = await form_hypotheses(finding, gateway=gateway)

    assert result.scope["src_ips"] == ["10.0.0.9"]
    assert result.scope["hostnames"] == ["DC-1"]
    assert result.scope["usernames"] == ["root"]


@pytest.mark.asyncio
async def test_source_techniques_are_merged_even_if_model_omits_them():
    # Model returns only its inferred technique; the source's T1071.004 must survive.
    gateway = FakeGateway(_valid_reply(attack_techniques=["T1568.002"]))
    result = await form_hypotheses(_botsv3_finding(), gateway=gateway)

    assert "T1071.004" in result.attack_techniques  # attested by the source
    assert "T1568.002" in result.attack_techniques  # inferred by the model


@pytest.mark.asyncio
async def test_reputation_reaches_the_prompt():
    gateway = FakeGateway(_valid_reply())

    await form_hypotheses(_botsv3_finding(), gateway=gateway)

    prompt = gateway.last_prompt
    assert "VT malicious=3" in prompt  # reputation fact reached the model
    assert "EvilCorp" in prompt


@pytest.mark.asyncio
async def test_prompt_declares_asset_context_unavailable():
    gateway = FakeGateway(_valid_reply())
    await form_hypotheses(_botsv3_finding(), gateway=gateway)

    assert "NOT AVAILABLE" in gateway.last_prompt  # the accepted asset-context gap


@pytest.mark.asyncio
async def test_reply_wrapped_in_prose_and_fences_is_parsed():
    fenced = "Here you go:\n```json\n" + _valid_reply() + "\n```\nHope this helps!"
    gateway = FakeGateway(fenced)
    result = await form_hypotheses(_botsv3_finding(), gateway=gateway)

    assert len(result.hypotheses) >= 1


@pytest.mark.asyncio
async def test_dict_reply_content_is_parsed():
    gateway = FakeGateway({"content": _valid_reply()})
    result = await form_hypotheses(_botsv3_finding(), gateway=gateway)

    assert len(result.hypotheses) >= 1


@pytest.mark.asyncio
async def test_malformed_reply_raises_cleanly():
    gateway = FakeGateway("I could not analyze this alert, sorry.")
    with pytest.raises(HypothesizerError):
        await form_hypotheses(_botsv3_finding(), gateway=gateway)


@pytest.mark.asyncio
async def test_empty_hypotheses_is_rejected():
    gateway = FakeGateway(_valid_reply(hypotheses=[]))
    with pytest.raises(HypothesizerError):
        await form_hypotheses(_botsv3_finding(), gateway=gateway)


@pytest.mark.asyncio
async def test_blank_narrative_is_rejected():
    gateway = FakeGateway(_valid_reply(narrative="   "))
    with pytest.raises(HypothesizerError):
        await form_hypotheses(_botsv3_finding(), gateway=gateway)


@pytest.mark.asyncio
async def test_finding_without_id_raises():
    finding = _botsv3_finding()
    del finding["finding_id"]
    gateway = FakeGateway(_valid_reply())
    with pytest.raises(HypothesizerError):
        await form_hypotheses(finding, gateway=gateway)


@pytest.mark.asyncio
async def test_empty_reply_raises():
    gateway = FakeGateway("")
    with pytest.raises(HypothesizerError):
        await form_hypotheses(_botsv3_finding(), gateway=gateway)
