import pytest
import json
from backend.agents.detection_rule_generator import DetectionRuleGeneratorAgent

class MockAIChoice:
    def __init__(self, content):
        self.message = {"content": content}

class MockAIResponse(dict):
    def __init__(self, content):
        super().__init__(choices=[MockAIChoice(content)])
        self["choices"] = [{"message": {"content": content}}]

def mock_openai_success(*args, **kwargs):
    return MockAIResponse(json.dumps({
        "title": "Mock Rule",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"EventID": 4624}},
        "level": "Mock Level"
    }))

def mock_openai_failure(*args, **kwargs):
    return MockAIResponse("Invalid JSON")

def test_rule_generation_splunk_windows(monkeypatch):
    import openai
    monkeypatch.setattr(openai.ChatCompletion, "create", mock_openai_success)
    agent = DetectionRuleGeneratorAgent()
    finding = {
        "type": "rdp_lateral_movement",
        "source": "windows",
        "description": "Multiple RDP logins",
        "severity": "high"
    }
    result = agent.run(finding, "T1021.001", target="splunk")
    assert "sigma" in result
    assert "formatted" in result
    assert result["sigma"]["tags"][0] == "attack.T1021.001"
    assert result["sigma"]["source"] == "auto-generated"
    assert "falsepositives" in result["sigma"]
    assert result["sigma"]["logsource"]["product"] == "windows"
    assert "index=* EventID=4624" in result["formatted"]
    assert "Legitimate RDP by IT admins" in result["sigma"]["falsepositives"]

def test_rule_generation_elastic_linux(monkeypatch):
    import openai
    monkeypatch.setattr(openai.ChatCompletion, "create", mock_openai_success)
    agent = DetectionRuleGeneratorAgent()
    finding = {
        "type": "ssh_brute_force",
        "source": "linux",
        "description": "Failed SSH",
        "severity": "medium"
    }
    result = agent.run(finding, "T1110.001", target="elastic")
    assert result["sigma"]["logsource"]["product"] == "linux"
    assert result["sigma"]["severity"] == "medium"
    assert result["formatted"] == "{'selection': {'EventID': 4624}}"
    assert "Legitimate activity" in result["sigma"]["falsepositives"]

def test_rule_generation_sigma_network(monkeypatch):
    import openai
    monkeypatch.setattr(openai.ChatCompletion, "create", mock_openai_success)
    agent = DetectionRuleGeneratorAgent()
    finding = {
        "type": "c2_beacon",
        "source": "network",
        "description": "C2 activity",
    }
    result = agent.run(finding, "T1071.001", target="sigma")
    assert result["sigma"]["logsource"]["product"] == "network"
    assert result["formatted"] == result["sigma"] # Target is sigma, should return raw dict

def test_ai_failure(monkeypatch):
    import openai
    monkeypatch.setattr(openai.ChatCompletion, "create", mock_openai_failure)
    agent = DetectionRuleGeneratorAgent()
    finding = {"type": "test"}
    with pytest.raises(Exception, match="AI failed to generate rule"):
        agent.run(finding, "T1234", target="sigma")

def test_validation_failure(monkeypatch):
    import openai
    # Missing 'detection' field
    def mock_invalid_schema(*args, **kwargs):
        return MockAIResponse(json.dumps({
            "title": "Mock Rule",
            "logsource": "windows"
        }))
    monkeypatch.setattr(openai.ChatCompletion, "create", mock_invalid_schema)
    agent = DetectionRuleGeneratorAgent()
    finding = {"type": "test"}
    with pytest.raises(Exception, match="Invalid Sigma rule generated"):
        agent.run(finding, "T1234", target="sigma")
