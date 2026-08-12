import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.agents import internal_auth, tools_router

BOUNDS = {"max_rows": 2, "timeout_ms": 500}
AUTH = {"Authorization": "Bearer shhh"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(internal_auth, "get_secret", lambda name: "shhh")
    app = FastAPI()
    app.include_router(tools_router.router, prefix=tools_router.ROUTER_META.prefix)
    return TestClient(app, client=("127.0.0.1", 50000))


def _answers(monkeypatch, result, handled=True):
    async def fake(name, args, **kwargs):
        return result, handled

    monkeypatch.setattr(tools_router, "execute_backend_tool", fake)


def _raises(monkeypatch, error):
    async def fake(name, args, **kwargs):
        raise error

    monkeypatch.setattr(tools_router, "execute_backend_tool", fake)


def _invoke(client, tool="list_findings", args=None, bounds=None, headers=AUTH):
    body = {"tool": tool, "args": args or {}, "bounds": bounds or BOUNDS}
    return client.post("/internal/tools/invoke", json=body, headers=headers)


class TestAuthorisation:
    def test_refuses_without_a_token(self, client):
        assert _invoke(client, headers={}).status_code == 401

    def test_refuses_a_wrong_token(self, client):
        assert (
            _invoke(client, headers={"Authorization": "Bearer nope"}).status_code == 401
        )

    def test_says_so_when_no_secret_is_configured(self, client, monkeypatch):
        """A deployment that never set the token must not read as a bad caller."""
        monkeypatch.setattr(internal_auth, "get_secret", lambda name: None)
        response = _invoke(client)
        assert response.status_code == 503
        assert "AGENT_INTERNAL_TOKEN" in response.json()["detail"]

    def test_refuses_a_caller_that_is_not_loopback(self, client, monkeypatch):
        monkeypatch.setattr(internal_auth, "_loopback", lambda request: False)
        assert _invoke(client).status_code == 403

    def test_a_loopback_bearer_gets_through(self, client, monkeypatch):
        _answers(monkeypatch, [])
        assert _invoke(client).status_code == 200


class TestBoundsAtTheSource:
    def test_caps_rows_and_says_it_capped(self, client, monkeypatch):
        _answers(monkeypatch, [{"id": 1}, {"id": 2}, {"id": 3}])
        body = _invoke(client).json()
        assert body["rows"] == [{"id": 1}, {"id": 2}]
        assert body["rowCount"] == 2
        assert body["capped"] is True

    def test_does_not_claim_capped_when_it_fitted(self, client, monkeypatch):
        _answers(monkeypatch, [{"id": 1}])
        body = _invoke(client).json()
        assert body["rowCount"] == 1
        assert body["capped"] is False

    def test_a_single_mapping_is_one_row_not_none(self, client, monkeypatch):
        _answers(monkeypatch, {"total": 7})
        body = _invoke(client).json()
        assert body["rows"] == [{"total": 7}]
        assert body["rowCount"] == 1

    def test_a_tool_over_its_timeout_reports_timeout(self, client, monkeypatch):
        async def slow(name, args, **kwargs):
            await asyncio.sleep(1)
            return [], True

        monkeypatch.setattr(tools_router, "execute_backend_tool", slow)
        body = _invoke(client, bounds={"max_rows": 2, "timeout_ms": 20}).json()
        assert body == {"ok": False, "failure": {"kind": "timeout", "timeoutMs": 20}}


class TestFailureKinds:
    def test_an_unknown_tool_is_a_defect_not_a_gap(self, client, monkeypatch):
        _answers(monkeypatch, None, handled=False)
        body = _invoke(client, tool="no_such_tool").json()
        assert body["failure"]["kind"] == "refused"

    def test_an_in_band_error_is_read_back_out_as_refused(self, client, monkeypatch):
        _answers(monkeypatch, {"error": "Unknown tool: list_findings"})
        assert _invoke(client).json()["failure"]["kind"] == "refused"

    def test_bad_arguments_are_invalid_args(self, client, monkeypatch):
        _raises(monkeypatch, TypeError("unexpected keyword argument 'nope'"))
        assert _invoke(client).json()["failure"]["kind"] == "invalid_args"

    def test_anything_else_is_a_backend_error(self, client, monkeypatch):
        _raises(monkeypatch, RuntimeError("the database went away"))
        assert _invoke(client).json()["failure"]["kind"] == "backend_error"

    def test_rejects_bounds_that_are_not_positive(self, client):
        assert (
            _invoke(client, bounds={"max_rows": 0, "timeout_ms": 500}).status_code
            == 422
        )
