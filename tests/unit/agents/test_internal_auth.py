# The one gate every /internal endpoint shares. A loopback check used to stand in
# front of it and refused every containerised caller before the token was read.

from __future__ import annotations

import pytest
from fastapi import HTTPException

from core.agents.internal_auth import TOKEN_SECRET, authorise

pytestmark = pytest.mark.unit


class _Request:
    client = None


@pytest.fixture()
def configured(monkeypatch):
    monkeypatch.setattr("core.agents.internal_auth.get_secret", lambda name: "s3cret" if name == TOKEN_SECRET else None)


def test_a_matching_token_is_accepted(configured):
    authorise(_Request(), "Bearer s3cret", "test")


# The case the loopback check broke: the agent worker is its own pod, so its
# address is never 127.0.0.1 and the token has to be what carries the call.
def test_a_caller_off_loopback_is_accepted_with_the_token(configured):
    authorise(_Request(), "Bearer s3cret", "test")


@pytest.mark.parametrize("presented", [None, "", "Bearer wrong", "s3cret", "Bearer s3cre"])
def test_anything_else_is_refused(configured, presented):
    with pytest.raises(HTTPException) as raised:
        authorise(_Request(), presented, "test")
    assert raised.value.status_code == 401


# 503, not 401: a deployment that never set the secret and a caller with the wrong
# one read identically otherwise, and the fix for each is nothing alike.
def test_an_unconfigured_secret_is_told_apart_from_a_bad_one(monkeypatch):
    monkeypatch.setattr("core.agents.internal_auth.get_secret", lambda name: None)
    with pytest.raises(HTTPException) as raised:
        authorise(_Request(), "Bearer anything", "test")
    assert raised.value.status_code == 503
