import pytest
import json
from unittest.mock import MagicMock, AsyncMock
from backend.services.detection_rule_service import DetectionRuleService
from backend.services.rule_formatter import RuleFormatter

@pytest.fixture
def mock_llm_gateway(monkeypatch):
    mock = AsyncMock()
    monkeypatch.setattr("backend.services.detection_rule_service.get_llm_gateway", lambda: mock)
    return mock

@pytest.fixture
def mock_db_manager(monkeypatch):
    mock = MagicMock()
    monkeypatch.setattr("backend.services.detection_rule_service.get_db_manager", lambda: mock)
    return mock

def test_sanitize_finding_whitelisting():
    service = DetectionRuleService()
    finding = {
        "finding_id": "F-123",
        "data_source": "syslog",
        "description": "Normal description",
        "secret_internal_field": "HACK",
        "mitre_predictions": {"technique_id": "T1059"}
    }
    sanitized = service.sanitize_finding(finding)
    
    assert "finding_id" in sanitized
    assert "secret_internal_field" not in sanitized
    assert sanitized["finding_id"] == "F-123"

def test_sanitize_finding_truncation():
    service = DetectionRuleService()
    long_desc = "A" * 2000
    finding = {"description": long_desc}
    sanitized = service.sanitize_finding(finding)
    
    assert len(sanitized["description"]) == 1000

def test_formatter_sanitization_vulnerability():
    formatter = RuleFormatter()
    # Attempted SPL injection
    unsafe_val = 'admin" | delete index=* | search "'
    safe_val = formatter.sanitize_value(unsafe_val)
    
    # Quotes should be escaped and pipe commands stripped
    assert '\\"' in safe_val
    assert "|" not in safe_val
    assert "delete" not in safe_val

def test_sigma_to_spl_conversion():
    formatter = RuleFormatter()
    rule = {
        "detection": {
            "selection": {
                "EventID": 4624,
                "User": "admin"
            }
        }
    }
    spl = formatter.sigma_to_spl(rule)
    assert 'index=*' in spl
    assert 'EventID="4624"' in spl
    assert 'User="admin"' in spl

@pytest.mark.asyncio
async def test_idempotency_deduplication(mock_llm_gateway, mock_db_manager):
    service = DetectionRuleService()
    finding = {"finding_id": "F-DUP", "mitre_predictions": {"technique_id": "T1059"}}
    
    rule_data = {
        "title": "Duplicate Rule",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"Field": "Value"}}
    }
    
    mock_llm_gateway.submit_insights.return_value = {"content": json.dumps(rule_data)}
    
    # Mock first call returns a new rule, second call returns existing
    session = mock_db_manager.session_scope.return_value.__enter__.return_value
    session.query.return_value.filter.return_value.first.side_effect = [None, MagicMock(id=1, sigma_rule=rule_data)]
    
    # First generation
    rule1 = await service.generate_rule(finding)
    assert rule1 is not None
    
    # Second generation (same data)
    rule2 = await service.generate_rule(finding)
    assert rule2 is not None
    assert rule2.id == 1 # Should return the mocked existing rule

def test_confidence_heuristic():
    service = DetectionRuleService()
    finding = {"data_source": "windows"}
    rule_simple = {
        "logsource": {"product": "windows"},
        "detection": {"selection": {"EventID": 1}}
    }
    rule_complex = {
        "logsource": {"product": "windows"},
        "detection": {"selection": {"EventID": 1, "User": "admin", "Target": "process"}}
    }
    
    conf_low = service._calculate_hybrid_confidence(rule_simple, finding)
    conf_high = service._calculate_hybrid_confidence(rule_complex, finding)
    
    assert conf_high > conf_low
    assert conf_high >= 70 # (15 structural + 20 context + 20 validation + 10 complexity)
