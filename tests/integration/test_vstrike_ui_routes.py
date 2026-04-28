"""Integration tests for the VStrike UI control plane routes.

These exercise:
  - POST /ui/iframe-token   → returns short-lived token + iframe URL
  - GET  /ui/networks       → returns network list
  - POST /ui/load-network   → triggers VStrike to update its iframe

The handlers resolve a `VStrikeService` via `get_vstrike_service()`. We
patch that factory to return a `MagicMock` so no live VStrike or HTTP is
needed.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT, ROOT / "backend"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

os.environ.setdefault("DEV_MODE", "true")


def _mock_ui_service(**overrides):
    svc = MagicMock()
    svc.base_url = overrides.get("base_url", "https://vstrike.example.com")
    svc.has_ui_credentials = overrides.get("has_ui_credentials", True)
    svc.has_api_credentials = overrides.get("has_api_credentials", True)
    svc.get_ui_login_token.return_value = overrides.get("ui_login_token", "tok-xyz")
    svc.list_networks.return_value = overrides.get(
        "networks", [{"id": "n-1", "name": "Prod"}]
    )
    svc.load_network_in_ui.return_value = overrides.get("load_result", {"ok": True})
    return svc


# --------------------------------------------------------------------------- #
# /ui/iframe-token
# --------------------------------------------------------------------------- #


def test_iframe_token_returns_token_and_url():
    from backend.api import vstrike as vstrike_module

    svc = _mock_ui_service(base_url="https://vstrike.net", ui_login_token="tok-abc")
    with patch.object(vstrike_module, "get_vstrike_service", return_value=svc):
        result = asyncio.run(vstrike_module.ui_iframe_token())

    assert result["token"] == "tok-abc"
    assert result["iframe_url"] == "https://vstrike.net/login?token=tok-abc"
    svc.get_ui_login_token.assert_called_once_with()


def test_iframe_token_503_when_ui_credentials_missing():
    from backend.api import vstrike as vstrike_module

    svc = _mock_ui_service(has_ui_credentials=False)
    with patch.object(vstrike_module, "get_vstrike_service", return_value=svc):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(vstrike_module.ui_iframe_token())

    assert exc_info.value.status_code == 503
    detail = exc_info.value.detail
    assert isinstance(detail, dict)
    assert "username" in detail["missing"]
    assert "password" in detail["missing"]


def test_iframe_token_503_when_service_not_configured():
    from backend.api import vstrike as vstrike_module

    with patch.object(vstrike_module, "get_vstrike_service", return_value=None):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(vstrike_module.ui_iframe_token())

    assert exc_info.value.status_code == 503


def test_iframe_token_502_when_upstream_fails():
    from backend.api import vstrike as vstrike_module

    svc = _mock_ui_service()
    svc.get_ui_login_token.side_effect = RuntimeError("upstream blew up")
    with patch.object(vstrike_module, "get_vstrike_service", return_value=svc):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(vstrike_module.ui_iframe_token())

    assert exc_info.value.status_code == 502
    assert "upstream" in str(exc_info.value.detail)


# --------------------------------------------------------------------------- #
# /ui/networks
# --------------------------------------------------------------------------- #


def test_list_networks_returns_payload():
    from backend.api import vstrike as vstrike_module

    networks = [
        {"id": "n-1", "name": "Prod"},
        {"id": "n-2", "name": "Lab"},
    ]
    svc = _mock_ui_service(networks=networks)
    with patch.object(vstrike_module, "get_vstrike_service", return_value=svc):
        result = asyncio.run(vstrike_module.ui_list_networks())

    assert result == {"networks": networks}


def test_list_networks_503_without_ui_credentials():
    from backend.api import vstrike as vstrike_module

    svc = _mock_ui_service(has_ui_credentials=False)
    with patch.object(vstrike_module, "get_vstrike_service", return_value=svc):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(vstrike_module.ui_list_networks())

    assert exc_info.value.status_code == 503


# --------------------------------------------------------------------------- #
# /ui/load-network
# --------------------------------------------------------------------------- #


def test_load_network_calls_service_with_network_id():
    from backend.api import vstrike as vstrike_module
    from backend.api.vstrike import VStrikeLoadNetworkRequest

    svc = _mock_ui_service()
    with patch.object(vstrike_module, "get_vstrike_service", return_value=svc):
        result = asyncio.run(
            vstrike_module.ui_load_network(
                VStrikeLoadNetworkRequest(network_id="net-42")
            )
        )

    assert result["ok"] is True
    svc.load_network_in_ui.assert_called_once_with("net-42")


def test_load_network_502_when_upstream_fails():
    from backend.api import vstrike as vstrike_module
    from backend.api.vstrike import VStrikeLoadNetworkRequest

    svc = _mock_ui_service()
    svc.load_network_in_ui.side_effect = RuntimeError("connection refused")
    with patch.object(vstrike_module, "get_vstrike_service", return_value=svc):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                vstrike_module.ui_load_network(
                    VStrikeLoadNetworkRequest(network_id="n")
                )
            )

    assert exc_info.value.status_code == 502
    assert "connection refused" in str(exc_info.value.detail)


# --------------------------------------------------------------------------- #
# /ui/killchain-replay
# --------------------------------------------------------------------------- #


def _make_killchain_request(**overrides):
    from backend.api.vstrike import (
        VStrikeKillchainReplayRequest,
        VStrikeKillchainStep,
    )

    return VStrikeKillchainReplayRequest(
        network_id=overrides.get("network_id", "net-1"),
        steps=overrides.get(
            "steps",
            [
                VStrikeKillchainStep(
                    node_id="asset-001",
                    timestamp="2026-04-28T11:00:00Z",
                    label="Initial Access",
                ),
                VStrikeKillchainStep(
                    node_id="asset-077",
                    timestamp="2026-04-28T11:12:00Z",
                    technique="T1003.001",
                    label="Target",
                ),
            ],
        ),
        loop=overrides.get("loop", False),
        auto_play=overrides.get("auto_play", True),
    )


def test_killchain_replay_passes_steps_to_service():
    from backend.api import vstrike as vstrike_module

    svc = _mock_ui_service()
    svc.killchain_replay_in_ui.return_value = {"ok": True, "queued": 2}
    with patch.object(vstrike_module, "get_vstrike_service", return_value=svc):
        result = asyncio.run(
            vstrike_module.ui_killchain_replay(_make_killchain_request())
        )

    assert result["ok"] is True
    svc.killchain_replay_in_ui.assert_called_once()
    args, kwargs = svc.killchain_replay_in_ui.call_args
    assert args[0] == "net-1"
    steps = args[1]
    assert [s["node_id"] for s in steps] == ["asset-001", "asset-077"]
    # exclude_none must drop unset optional fields.
    assert "technique" not in steps[0]
    assert steps[1]["technique"] == "T1003.001"
    assert kwargs == {"loop": False, "auto_play": True}


def test_killchain_replay_501_when_tool_not_implemented():
    from backend.api import vstrike as vstrike_module
    from services.vstrike_service import VStrikeToolNotImplemented

    svc = _mock_ui_service()
    svc.killchain_replay_in_ui.side_effect = VStrikeToolNotImplemented(
        "VStrike server does not yet implement ui-killchain-replay."
    )
    with patch.object(vstrike_module, "get_vstrike_service", return_value=svc):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(vstrike_module.ui_killchain_replay(_make_killchain_request()))

    assert exc_info.value.status_code == 501
    assert "ui-killchain-replay" in str(exc_info.value.detail)


def test_killchain_replay_502_on_other_runtime_errors():
    from backend.api import vstrike as vstrike_module

    svc = _mock_ui_service()
    svc.killchain_replay_in_ui.side_effect = RuntimeError("transport failed")
    with patch.object(vstrike_module, "get_vstrike_service", return_value=svc):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(vstrike_module.ui_killchain_replay(_make_killchain_request()))

    assert exc_info.value.status_code == 502
    assert "transport failed" in str(exc_info.value.detail)


def test_killchain_replay_503_without_ui_credentials():
    from backend.api import vstrike as vstrike_module

    svc = _mock_ui_service(has_ui_credentials=False)
    with patch.object(vstrike_module, "get_vstrike_service", return_value=svc):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(vstrike_module.ui_killchain_replay(_make_killchain_request()))

    assert exc_info.value.status_code == 503
