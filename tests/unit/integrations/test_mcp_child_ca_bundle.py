"""The CA bundle reaching a spawned MCP tool server.

The servers run on httpx, which reads SSL_CERT_FILE/SSL_CERT_DIR and ignores
REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE. Two things have to hold: the legacy names
translate, and the result is passed explicitly, because stdio_client narrows the
child environment to a six-name allowlist.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from mcp.client.stdio import get_default_environment

from core.integrations.mcp.child_env import ca_bundle_env

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[3]

# Where a tool server gets spawned. A new one that forgets the bundle is the
# failure mode this guards: it works everywhere except behind a private CA.
SPAWN_MODULES = (
    "core/integrations/mcp/service.py",
    "core/integrations/mcp/client.py",
)

_ALL_VARS = ("SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")


@pytest.fixture(autouse=True)
def _clear_bundle_vars(monkeypatch):
    for var in _ALL_VARS:
        monkeypatch.delenv(var, raising=False)


def test_no_bundle_configured_leaves_httpx_on_certifi():
    assert ca_bundle_env() == {}


@pytest.mark.parametrize("var", _ALL_VARS[:1] + _ALL_VARS[2:])
def test_a_file_bundle_arrives_as_ssl_cert_file(monkeypatch, tmp_path, var):
    """Whatever the operator called it, httpx only reads SSL_CERT_FILE."""
    bundle = tmp_path / "corporate-ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n")
    monkeypatch.setenv(var, str(bundle))

    assert ca_bundle_env() == {"SSL_CERT_FILE": str(bundle)}


def test_a_directory_bundle_arrives_as_ssl_cert_dir(monkeypatch, tmp_path):
    """cafile and capath are not interchangeable — route by what the path is."""
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path))

    assert ca_bundle_env() == {"SSL_CERT_DIR": str(tmp_path)}


def test_the_httpx_native_name_wins(monkeypatch, tmp_path):
    """An operator who already moved on is not overridden by a stale value."""
    current = tmp_path / "current.pem"
    current.write_text("x")
    legacy = tmp_path / "legacy.pem"
    legacy.write_text("x")
    monkeypatch.setenv("SSL_CERT_FILE", str(current))
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(legacy))

    assert ca_bundle_env() == {"SSL_CERT_FILE": str(current)}


def test_a_missing_path_falls_back_rather_than_breaking_tls(monkeypatch, tmp_path):
    """A stale path must not become an SSL_CERT_FILE that fails every call."""
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "gone.pem"))

    assert ca_bundle_env() == {}


def test_the_sdk_would_otherwise_strip_it(monkeypatch, tmp_path):
    """Why this is forwarded and not inherited.

    If stdio_client passed the parent environment through, none of the above
    would be needed. It doesn't — so guard the assumption.
    """
    bundle = tmp_path / "ca.pem"
    bundle.write_text("x")
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))

    assert "SSL_CERT_FILE" not in get_default_environment()


@pytest.mark.parametrize("rel", SPAWN_MODULES)
def test_every_spawn_site_forwards_the_bundle(rel):
    """One ca_bundle_env() per place a child environment is built."""
    src = (ROOT / rel).read_text()
    spawns = src.count("os.environ.copy()") + src.count("StdioServerParameters(")
    forwards = src.count("ca_bundle_env()")
    assert forwards >= spawns, (
        f"{rel} builds {spawns} child environment(s) but forwards the CA "
        f"bundle {forwards} time(s) — a server spawned without it fails TLS "
        "behind a private CA"
    )
