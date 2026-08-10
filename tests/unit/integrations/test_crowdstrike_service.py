"""Unit tests for services/crowdstrike_service.py (httpx transport, respx-mocked).

Covers the OAuth flow, the two-step detection fetch, and the containment
actions.
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import respx

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.integrations.crowdstrike.client import CrowdStrikeService  # noqa: E402

BASE = "https://api.crowdstrike.com"


def _service() -> CrowdStrikeService:
    return CrowdStrikeService(client_id="cid", client_secret="csec")


def _mock_auth() -> None:
    """CrowdStrike returns 201 (not 200) from its OAuth2 token endpoint."""
    respx.post(f"{BASE}/oauth2/token").mock(
        return_value=httpx.Response(
            201, json={"access_token": "tok-1", "expires_in": 1800}
        )
    )


def test_client_is_bounded_and_follows_redirects():
    svc = _service()
    assert svc.session.timeout.read == 30.0
    assert svc.session.follow_redirects is True


@respx.mock
def test_authenticate_sets_bearer_header():
    _mock_auth()
    svc = _service()

    assert svc._authenticate() is True
    assert svc.access_token == "tok-1"
    assert svc.session.headers["Authorization"] == "Bearer tok-1"


@respx.mock
def test_authenticate_returns_false_on_non_201():
    respx.post(f"{BASE}/oauth2/token").mock(return_value=httpx.Response(403))
    assert _service()._authenticate() is False


@respx.mock
def test_test_connection_success():
    _mock_auth()
    respx.get(f"{BASE}/sensors/queries/sensors/v1").mock(
        return_value=httpx.Response(200, json={"resources": []})
    )

    ok, message = _service().test_connection()
    assert ok is True, message


@respx.mock
def test_test_connection_handles_transport_error():
    respx.post(f"{BASE}/oauth2/token").mock(side_effect=httpx.ConnectError("refused"))
    ok, _ = _service().test_connection()
    assert ok is False


@respx.mock
def test_get_detections_resolves_ids_then_summaries():
    _mock_auth()
    query = respx.get(f"{BASE}/detects/queries/detects/v1").mock(
        return_value=httpx.Response(200, json={"resources": ["ldt:1", "ldt:2"]})
    )
    summaries = respx.post(f"{BASE}/detects/entities/summaries/GET/v1").mock(
        return_value=httpx.Response(
            200, json={"resources": [{"detection_id": "ldt:1"}]}
        )
    )

    result = _service().get_detections(filter_query="status:'new'", limit=50)

    assert result == [{"detection_id": "ldt:1"}]
    assert query.calls.last.request.url.params["filter"] == "status:'new'"
    assert query.calls.last.request.url.params["limit"] == "50"
    assert summaries.called


@respx.mock
def test_get_detections_short_circuits_when_no_ids():
    """No detection IDs must not trigger the summaries POST."""
    _mock_auth()
    respx.get(f"{BASE}/detects/queries/detects/v1").mock(
        return_value=httpx.Response(200, json={"resources": []})
    )
    summaries = respx.post(f"{BASE}/detects/entities/summaries/GET/v1").mock(
        return_value=httpx.Response(200, json={"resources": []})
    )

    assert _service().get_detections() == []
    assert not summaries.called


@respx.mock
def test_lift_containment_uses_the_lift_action():
    _mock_auth()
    action = respx.post(f"{BASE}/devices/entities/devices-actions/v2").mock(
        return_value=httpx.Response(202, json={})
    )

    result = _service().lift_containment("host-1")

    assert result["success"] is True
    assert action.calls.last.request.url.params["action_name"] == "lift_containment"


@respx.mock
def test_lift_containment_reports_failure_on_error_status():
    _mock_auth()
    respx.post(f"{BASE}/devices/entities/devices-actions/v2").mock(
        return_value=httpx.Response(500)
    )

    result = _service().lift_containment("host-1")
    assert result["success"] is False
