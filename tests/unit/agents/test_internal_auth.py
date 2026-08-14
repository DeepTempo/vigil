# The one gate every /internal endpoint shares, and since ADR 0014 the only one:
# a loopback check stood in front of it and refused every containerised caller.

from __future__ import annotations

import pytest
from fastapi import HTTPException

from core.agents.internal_auth import TOKEN_SECRET, authorise

pytestmark = pytest.mark.unit


@pytest.fixture()
def configured(monkeypatch):
    monkeypatch.setattr(
        "core.agents.internal_auth.get_secret",
        lambda name: "s3cret" if name == TOKEN_SECRET else None,
    )


# The agent worker is its own pod, so its address is never 127.0.0.1 and nothing
# but the token can carry the call.
def test_a_matching_token_is_accepted(configured):
    authorise("Bearer s3cret", "test")


@pytest.mark.parametrize(
    "presented", [None, "", "Bearer wrong", "s3cret", "Bearer s3cre"]
)
def test_anything_else_is_refused(configured, presented):
    with pytest.raises(HTTPException) as raised:
        authorise(presented, "test")
    assert raised.value.status_code == 401


# A token holding anything above U+00FF would throw out of compare_digest rather
# than be refused, and a 500 on a bad credential is a different answer.
def test_a_token_outside_latin_1_is_refused_rather_than_raised(configured):
    with pytest.raises(HTTPException) as raised:
        authorise("Bearer €", "test")
    assert raised.value.status_code == 401


# 503, not 401: a deployment that never set the secret and a caller with the wrong
# one read identically otherwise, and the fix for each is nothing alike.
def test_an_unconfigured_secret_is_told_apart_from_a_bad_one(monkeypatch):
    monkeypatch.setattr("core.agents.internal_auth.get_secret", lambda name: None)
    with pytest.raises(HTTPException) as raised:
        authorise("Bearer anything", "test")
    assert raised.value.status_code == 503
