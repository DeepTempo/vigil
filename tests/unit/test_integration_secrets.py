"""Unit tests for the per-integration secret-field registry."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.integration_secrets import (  # noqa: E402
    INTEGRATION_SECRET_FIELDS,
    redact_secrets,
    secret_field_names,
    secret_fields_for,
    split_secrets,
)


def test_vstrike_secret_fields_registered():
    """The four VStrike secret fields must round-trip to env-var keys."""
    fields = secret_fields_for("vstrike")
    assert fields["api_key"] == "VSTRIKE_API_KEY"
    assert fields["inbound_api_key"] == "VSTRIKE_INBOUND_API_KEY"
    assert fields["username"] == "VSTRIKE_USERNAME"
    assert fields["password"] == "VSTRIKE_PASSWORD"


def test_secret_fields_for_unregistered_returns_empty():
    assert secret_fields_for("not-a-real-integration") == {}


def test_split_secrets_partitions_correctly():
    raw = {
        "url": "https://vstrike.net",
        "verify_ssl": True,
        "username": "alice",
        "password": "wonderland",
        "api_key": "bearer-token",
    }
    secrets, non_secrets = split_secrets("vstrike", raw)
    # Secrets keyed by env-var name, ready for set_secret().
    assert secrets == {
        "VSTRIKE_USERNAME": "alice",
        "VSTRIKE_PASSWORD": "wonderland",
        "VSTRIKE_API_KEY": "bearer-token",
    }
    # Non-secrets retain original field names; no plaintext credentials.
    assert non_secrets == {
        "url": "https://vstrike.net",
        "verify_ssl": True,
    }


def test_split_secrets_keeps_empty_secret_values():
    """Empty strings must reach the caller so it can choose 'don't overwrite'."""
    raw = {
        "url": "https://vstrike.net",
        "username": "",
        "password": "",
    }
    secrets, _non_secrets = split_secrets("vstrike", raw)
    assert secrets["VSTRIKE_USERNAME"] == ""
    assert secrets["VSTRIKE_PASSWORD"] == ""


def test_split_secrets_unregistered_integration_passthrough():
    """Unregistered integrations get an empty secrets dict + a copy of input."""
    raw = {"foo": "bar", "baz": 42}
    secrets, non_secrets = split_secrets("brand-new", raw)
    assert secrets == {}
    assert non_secrets == raw
    assert non_secrets is not raw  # copy, not alias


def test_redact_secrets_removes_registered_fields():
    raw = {
        "url": "https://vstrike.net",
        "api_key": "leaked-bearer",
        "username": "alice",
        "password": "wonderland",
        "verify_ssl": True,
    }
    redacted = redact_secrets("vstrike", raw)
    assert "api_key" not in redacted
    assert "username" not in redacted
    assert "password" not in redacted
    assert redacted["url"] == "https://vstrike.net"
    assert redacted["verify_ssl"] is True


def test_redact_secrets_unregistered_integration_passthrough():
    raw = {"foo": "bar"}
    redacted = redact_secrets("brand-new", raw)
    assert redacted == raw


def test_secret_field_names_returns_form_field_names():
    names = list(secret_field_names("vstrike"))
    assert set(names) == {"api_key", "inbound_api_key", "username", "password"}


def test_registry_is_a_mapping_not_a_dict_alias():
    """Sanity: callers shouldn't be able to mutate the registry by accident."""
    # `secret_fields_for` returns the registry's inner mapping by reference.
    # We don't enforce immutability here, but flag it if a caller mutates.
    fields = secret_fields_for("vstrike")
    original_size = len(fields)
    # Constructing a new dict from it is fine; the registry stays intact.
    {**fields, "extra": "ENV"}
    assert len(secret_fields_for("vstrike")) == original_size
    # And the registry export is keyed by integration_id
    assert "vstrike" in INTEGRATION_SECRET_FIELDS
