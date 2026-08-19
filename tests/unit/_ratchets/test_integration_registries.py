"""The integration registries must agree with each other.

Five registries had drifted apart — ``mcp-config.json`` keys, descriptor ``id``,
descriptor server names, the frontend catalog, and the snake_case key each
vendor server passed to ``get_integration_config``. The damage was silent: six
servers read a key the Settings UI never writes, and every server name in the
bridge's map matched nothing at all.

The descriptor is now the source of truth. These assertions hold it to the two
registries it cannot generate: ``mcp-config.json`` and the frontend catalog.

Follows the ``config.py`` ↔ ``env.example`` precedent in
``test_settings_env_example.py``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from core.integrations._base.descriptor import iter_descriptors
from core.integrations.integration_secrets import INTEGRATION_SECRET_FIELDS

_REPO_ROOT = Path(__file__).resolve().parents[3]
_MCP_CONFIG = _REPO_ROOT / "mcp-config.json"
_CATALOG = _REPO_ROOT / "clients" / "web" / "src" / "config" / "integrations.ts"


def _mcp_server_keys() -> set[str]:
    servers = json.loads(_MCP_CONFIG.read_text())["mcpServers"]
    return {k for k, v in servers.items() if not isinstance(v, str)}


def _catalog() -> dict[str, dict[str, str]]:
    """Parse the frontend catalog into ``{id: {field_name: field_type}}``."""
    source = _CATALOG.read_text()
    entries: dict[str, dict[str, str]] = {}
    for block in re.split(r"\n  \{\n", source):
        found = re.search(r"id: *'([A-Za-z0-9_-]+)'", block)
        if not found:
            continue
        fields = re.findall(
            r"name: *'([A-Za-z_0-9]+)',\s*\n\s*label:[^\n]*\n\s*type: *'([a-z]+)'",
            block,
        )
        entries[found.group(1)] = dict(fields)
    return entries


def _descriptors():
    return sorted(iter_descriptors(), key=lambda d: d.id)


@pytest.mark.unit
def test_every_server_name_resolves_to_a_real_mcp_config_key():
    keys = _mcp_server_keys()
    dangling = {
        d.id: [name for name in d.mcp_server_names if name not in keys]
        for d in _descriptors()
        if any(name not in keys for name in d.mcp_server_names)
    }
    assert not dangling, (
        "descriptors naming MCP servers that do not exist in mcp-config.json: "
        f"{dangling}"
    )


@pytest.mark.unit
def test_every_descriptor_id_is_a_real_catalog_entry():
    catalog = _catalog()
    orphans = [d.id for d in _descriptors() if d.id not in catalog]
    assert not orphans, (
        "descriptors with no row in clients/web/src/config/integrations.ts, so "
        f"they can never be configured in the UI: {orphans}"
    )


@pytest.mark.unit
def test_descriptor_fields_match_the_catalog_form():
    """A field a server reads must be one the Settings form actually collects.

    Carbon Black read ``api_token`` while the form collected ``api_id`` and
    ``api_key``; Palo Alto read ``url`` while the form collected ``hostname``.
    Both resolved to None forever.
    """
    catalog = _catalog()
    mismatched = {}
    for descriptor in _descriptors():
        expected = set(catalog.get(descriptor.id, {}))
        declared = set(descriptor.field_names)
        if declared != expected:
            mismatched[descriptor.id] = {
                "declared_not_in_catalog": sorted(declared - expected),
                "in_catalog_not_declared": sorted(expected - declared),
            }
    assert not mismatched, f"descriptor/catalog field drift: {mismatched}"


@pytest.mark.unit
def test_every_catalog_password_field_is_stored_as_a_secret():
    """One-way: a password field must be secret, but a descriptor may protect
    more than the form marks (vstrike's username is read via get_secret)."""
    catalog = _catalog()
    unprotected = {}
    for integration_id, fields in catalog.items():
        passwords = {name for name, kind in fields.items() if kind == "password"}
        registered = set(INTEGRATION_SECRET_FIELDS.get(integration_id, {}))
        leaked = passwords - registered
        if leaked:
            unprotected[integration_id] = sorted(leaked)
    assert not unprotected, (
        "password fields that would be persisted in plaintext because nothing "
        f"registers them as secrets: {unprotected}"
    )


@pytest.mark.unit
def test_no_vendor_server_lives_in_the_tools_package():
    """``tools/`` holds only servers that talk to Vigil's own services."""
    strays = sorted(
        p.name for p in (_REPO_ROOT / "tools").glob("*.py") if p.name != "__init__.py"
    )
    assert not strays, (
        "vendor MCP servers must live in core/integrations/<vendor>/tool.py, "
        f"not tools/: {strays}"
    )
