"""Every declared field of every integration must actually resolve.

The bug this exists to prevent: a server reads its credential from
``get_integration_config``, which the save handler has already stripped it out
of, so the value is ``None`` forever and the server reports "not configured" no
matter what the operator types. Six servers shipped that way, plus three that
had already been moved into ``core/integrations/``.

The stored-config fixture below deliberately omits secret fields, exactly as
``split_secrets`` leaves them, so a server that looks for a credential in the
wrong place fails here.
"""

from __future__ import annotations

import pytest

import core.integrations._base.config as resolver
from core.integrations._base.config import missing, resolve
from core.integrations._base.descriptor import iter_descriptors
from core.integrations.integration_secrets import secret_fields_for, split_secrets

_DESCRIPTORS = sorted(iter_descriptors(), key=lambda d: d.id)

# Strings whatever the declared type: that is what the env channel hands the
# resolver, and coercing it is the resolver's job.
_SAMPLES = {
    "str": lambda name: f"stored-{name}",
    "bool": lambda _: "true",
    "int": lambda _: "7",
}

_EXPECTED = {"str": str, "bool": bool, "int": int}


@pytest.fixture
def seeded(monkeypatch):
    """Seed a stored config and a secrets store the way production writes them."""

    def _seed(descriptor):
        secret_names = set(descriptor.secret_fields)
        stored = {
            field.name: _SAMPLES[field.value_type](field.name)
            for field in descriptor.fields
            if field.name not in secret_names
        }
        secrets = {
            env_key: f"secret-{field}"
            for field, env_key in secret_fields_for(descriptor.id).items()
        }
        monkeypatch.setattr(
            resolver, "get_integration_config", lambda _id: dict(stored)
        )
        monkeypatch.setattr(
            resolver, "get_secret", lambda key, default=None: secrets.get(key, default)
        )
        return stored, secrets

    return _seed


@pytest.mark.unit
@pytest.mark.parametrize("descriptor", _DESCRIPTORS, ids=lambda d: d.id)
def test_every_declared_field_resolves(descriptor, seeded):
    seeded(descriptor)
    resolved = resolve(descriptor)

    assert set(resolved) == set(descriptor.field_names)
    empty = [n for n, value in resolved.items() if value is None or value == ""]
    assert not empty, f"{descriptor.id}: fields resolved to nothing: {empty}"

    wrong_type = {
        f.name: type(resolved[f.name]).__name__
        for f in descriptor.fields
        if not isinstance(resolved[f.name], _EXPECTED[f.value_type])
    }
    assert not wrong_type, (
        f"{descriptor.id}: fields reached the server with the wrong type: "
        f"{wrong_type} — this is how the string 'false' became a CA-bundle path"
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "descriptor", [d for d in _DESCRIPTORS if d.secret_fields], ids=lambda d: d.id
)
def test_secrets_come_from_the_secrets_store(descriptor, seeded):
    """A credential must resolve even though the stored config never holds it."""
    seeded(descriptor)
    resolved = resolve(descriptor)

    for field in descriptor.secret_fields:
        assert resolved[field] == f"secret-{field}", (
            f"{descriptor.id}.{field} did not come from the secrets store — this is "
            "the failure mode where a server reads a credential out of the "
            "stripped config and silently gets None"
        )


@pytest.mark.unit
@pytest.mark.parametrize(
    "descriptor", [d for d in _DESCRIPTORS if d.secret_fields], ids=lambda d: d.id
)
def test_split_secrets_really_strips_the_fields_servers_need(descriptor):
    """The premise: persisted config cannot contain a registered secret."""
    submitted = {name: "typed-by-operator" for name in descriptor.field_names}
    _, non_secrets = split_secrets(descriptor.id, submitted)

    for field in descriptor.secret_fields:
        assert field not in non_secrets


@pytest.mark.unit
def test_missing_reports_unresolved_fields():
    assert missing({"url": "x", "api_key": ""}, "url", "api_key") == ("api_key",)
    assert missing({"url": "x"}, "url") == ()
