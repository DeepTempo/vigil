"""Tests for the application-wide exception handlers.

The contract these lock down: routes no longer wrap themselves in
``try``/``except`` to produce an HTTP error, so the handlers must render domain
errors with the right status, must not leak internal exception text, and must
still emit CORS headers on a 500 — otherwise a browser reports an opaque CORS
failure instead of the error.
"""

import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from core.exceptions import DatabaseError, SOCError
from services.api.errors import register_exception_handlers

pytestmark = pytest.mark.unit

ORIGIN = "http://localhost:6988"

SECRET = "postgresql://vigil:hunter2@db:5432/vigil"


class _Conflict(SOCError):
    """Stand-in for a domain error that picks a non-default status."""

    status_code = 409

    def __init__(self, message: str):
        super().__init__(message, "CONFLICT")


@pytest.fixture
def client():
    """An app wired exactly as main.py wires it: handlers, then CORS."""
    app = FastAPI()
    register_exception_handlers(app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[ORIGIN],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/boom")
    def boom():
        raise RuntimeError(SECRET)

    @app.get("/conflict")
    def conflict():
        raise _Conflict("case already closed")

    @app.get("/database")
    def database():
        raise DatabaseError("could not reach the database")

    @app.get("/subclass")
    def subclass():
        class NarrowerConflict(_Conflict):
            pass

        raise NarrowerConflict("nope")

    @app.get("/ok")
    def ok():
        return {"ok": True}

    return TestClient(app, raise_server_exceptions=False)


def test_unhandled_exception_is_500_and_leaks_nothing(client):
    r = client.get("/boom")
    assert r.status_code == 500
    assert r.json()["detail"] == "Internal server error"
    assert r.json()["code"] == "INTERNAL_ERROR"
    assert SECRET not in r.text
    assert "hunter2" not in r.text


def test_cors_headers_present_on_unhandled_500(client):
    """Regression: Starlette's Exception handler runs outside CORSMiddleware."""
    r = client.get("/boom", headers={"Origin": ORIGIN})
    assert r.status_code == 500
    assert r.headers["access-control-allow-origin"] == ORIGIN


def test_cors_headers_present_on_domain_error(client):
    r = client.get("/conflict", headers={"Origin": ORIGIN})
    assert r.status_code == 409
    assert r.headers["access-control-allow-origin"] == ORIGIN


@pytest.mark.parametrize(
    "path,status,code",
    [
        ("/conflict", 409, "CONFLICT"),
        ("/database", 500, "DATABASE_ERROR"),
    ],
)
def test_domain_errors_map_to_status(client, path, status, code):
    r = client.get(path)
    assert r.status_code == status
    assert r.json()["code"] == code


def test_domain_error_message_is_preserved(client):
    """SOCError messages are chosen by us, so they are safe to return."""
    assert client.get("/conflict").json()["detail"] == "case already closed"


def test_plain_soc_error_defaults_to_500(client):
    """A SOCError that sets no status_code must not 200 or crash."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/custom")
    def custom():
        raise SOCError("something else", code="CUSTOM")

    r = TestClient(app, raise_server_exceptions=False).get("/custom")
    assert r.status_code == 500
    assert r.json()["code"] == "CUSTOM"


def test_subclass_inherits_status_code(client):
    r = client.get("/subclass")
    assert r.status_code == 409


def test_success_path_untouched(client):
    r = client.get("/ok", headers={"Origin": ORIGIN})
    assert r.status_code == 200
    assert r.json() == {"ok": True}
