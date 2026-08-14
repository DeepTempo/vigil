"""Resolve a Vendor Slice's configuration from its descriptor.

The one way an MCP server reads its own config. Non-secret fields come from the
stored integration config; secret fields come from the encrypted store, keyed by
the same names ``integration_secrets`` writes them under.

Reading a credential straight from ``get_integration_config`` cannot work:
``split_secrets`` strips every registered secret field before anything is
persisted, so the credential is never in the JSON or the DB. Several servers did
exactly that and silently ran with ``None`` — this module exists so no server has
to know the rule.

``resolve`` is the descriptor-driven entry point. ``resolve_fields`` takes an
explicit field list for callers with no descriptor, such as a generated custom
integration.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping, Optional

from core.config import get_integration_config
from core.integrations._base.descriptor import IntegrationDescriptor
from core.integrations.integration_secrets import default_env_var, secret_fields_for
from core.secrets import get_secret


def resolve_fields(
    integration_id: str, field_names: Iterable[str]
) -> Dict[str, Optional[Any]]:
    """Resolve named fields for an integration, secrets included.

    A non-secret falls back to ``get_secret`` when the stored config has no
    value: that is the channel an ``mcp-config.json`` ``env`` block feeds, and
    it keeps env-configured servers working without a raw environment read.
    """
    stored: Mapping[str, Any] = get_integration_config(integration_id) or {}
    secret_keys = secret_fields_for(integration_id)

    resolved: Dict[str, Optional[Any]] = {}
    for name in field_names:
        env_key = secret_keys.get(name)
        if env_key is not None:
            resolved[name] = get_secret(env_key)
            continue
        value = stored.get(name)
        if value is None or value == "":
            value = get_secret(default_env_var(integration_id, name))
        resolved[name] = value
    return resolved


def resolve(descriptor: IntegrationDescriptor) -> Dict[str, Optional[Any]]:
    """Resolve every field the descriptor declares."""
    return resolve_fields(descriptor.id, descriptor.field_names)


def missing(config: Mapping[str, Any], *required: str) -> tuple[str, ...]:
    """Which of ``required`` resolved to nothing — the 'not configured' check."""
    return tuple(name for name in required if not config.get(name))
