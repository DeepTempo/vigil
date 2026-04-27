"""Per-integration registry of secret-typed configuration fields.

Vigil's persistence story for integration credentials is split:

- **Non-secret config** (URLs, regions, verify_ssl flags, paths) goes into the
  ``IntegrationConfig`` database table via ``database.config_service`` and is
  mirrored to ``~/.deeptempo/integrations_config.json`` for back-compat.
- **Secret credentials** (API keys, passwords, bearer tokens) go into the
  encrypted secrets store at ``~/.vigil/secrets.enc`` via
  ``backend.secrets_manager.set_secret`` / ``get_secret``.

This module exposes the mapping from frontend form-field name → environment
variable name (which is also the secrets-store key) for each integration's
secret-typed fields. The generic ``POST /config/integrations`` save handler
uses it to:

1. Route the value of each registered secret field through ``set_secret`` so
   the credential lands in the encrypted store (and ``os.environ`` for the
   in-process backend, see ``SecretsManager.set``).
2. Strip the field from the dict that gets persisted to the DB / JSON, so we
   never write plaintext credentials to those stores.
3. On read, redact the same fields from the response so secrets don't leak
   back to the frontend.

When you add a new integration that has password-typed fields in
``frontend/src/config/integrations.ts``, add a matching entry here.
"""

from __future__ import annotations

from typing import Dict, Iterable, Mapping

# integration_id → {form_field_name: secrets_manager_key}
INTEGRATION_SECRET_FIELDS: Mapping[str, Mapping[str, str]] = {
    "vstrike": {
        "api_key": "VSTRIKE_API_KEY",
        "inbound_api_key": "VSTRIKE_INBOUND_API_KEY",
        "username": "VSTRIKE_USERNAME",
        "password": "VSTRIKE_PASSWORD",
    },
}


def secret_fields_for(integration_id: str) -> Mapping[str, str]:
    """Return the secret-field map for an integration, empty if unregistered."""
    return INTEGRATION_SECRET_FIELDS.get(integration_id, {})


def split_secrets(
    integration_id: str, config: Dict[str, object]
) -> tuple[Dict[str, str], Dict[str, object]]:
    """Partition a config dict into (secrets, non_secrets).

    `secrets` maps secrets-store key → value (ready to feed `set_secret`).
    Empty-string and `None` values are kept in `secrets` so the caller can
    decide whether to apply or skip them (the convention is "empty means
    don't overwrite an existing secret").

    The returned non_secrets dict is a fresh copy with secret fields
    removed — safe to persist to the DB / JSON.
    """
    mapping = secret_fields_for(integration_id)
    if not mapping:
        return {}, dict(config)

    secrets: Dict[str, str] = {}
    non_secrets: Dict[str, object] = {}
    for field, value in config.items():
        env_key = mapping.get(field)
        if env_key is None:
            non_secrets[field] = value
            continue
        # Coerce to string so callers don't have to. Non-string values for
        # secret fields are pathological — log via the redact step if needed.
        secrets[env_key] = "" if value is None else str(value)
    return secrets, non_secrets


def redact_secrets(integration_id: str, config: Dict[str, object]) -> Dict[str, object]:
    """Return a copy of ``config`` with registered secret fields removed.

    Used by the GET handler so the frontend never receives plaintext
    credentials. The form will treat absent secret fields as "leave existing
    value untouched" on the next save.
    """
    mapping = secret_fields_for(integration_id)
    if not mapping:
        return dict(config)
    return {k: v for k, v in config.items() if k not in mapping}


def secret_field_names(integration_id: str) -> Iterable[str]:
    """Iterable over the form-field names that are secrets for an integration."""
    return secret_fields_for(integration_id).keys()
