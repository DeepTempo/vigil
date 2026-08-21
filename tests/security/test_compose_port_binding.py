"""Port inventory: every service Compose starts by default must publish its
ports on loopback, or be on the explicit remote-consumer allowlist.

Locks in the contract from issue #587. ``infra/docker/docker-compose.yml``
published Postgres, Redis and Bifrost with a bare ``"5432:5432"``-style
mapping, which Docker binds to ``0.0.0.0`` — reachable from anywhere on the
operator's LAN. On a SOC box that is a real exposure: Postgres ships a default
password that lives in this repo and holds ``findings``, ``cases`` and
``llm_provider_configs``; Redis runs with no ``requirepass`` at all; and
Bifrost serves an unauthenticated admin API on its inference port, including
``PUT /api/providers/{name}/keys/{key_id}``.

None of those three has a consumer outside the host — the backend, daemon and
workers all reach them by service name over the ``deeptempo-network`` bridge,
and a host-run backend reaches them over loopback. Binding them to
``127.0.0.1`` costs nothing and closes the hole.

If you add a service that publishes a port and this test fails, the fix is to
write the mapping as ``"127.0.0.1:<host>:<container>"``. Adding a service to
``REMOTE_CONSUMERS`` is a security decision, not a way to make this test quiet:
it asserts that something off-box is *supposed* to connect. ``backend`` is
there because analysts browse to it, and ``soc-daemon`` because SIEMs push
webhooks to it and Prometheus scrapes it.

Scope note: this gate covers only the services that start on a plain
``docker compose up``. Services behind an opt-in profile (``pgadmin`` on
``dev``, the ``observability`` stack, ``splunk``, ``kafka``) are started by a
deliberate operator action and are out of scope here. ``pgadmin`` in
particular still publishes ``5050`` on all interfaces with a default password
and its login disabled; that is tracked separately as issue #707. When #707
lands, widen this gate to cover profile-gated services and drop this note.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parent.parent.parent
COMPOSE = REPO / "infra" / "docker" / "docker-compose.yml"

LOOPBACK = "127.0.0.1"

# Services whose ports are meant to be reachable from another machine.
# See the module docstring before adding to this set.
REMOTE_CONSUMERS = {
    "backend",     # analyst browsers hit the API + SPA on 6987
    "soc-daemon",  # SIEM webhook push (8081), Prometheus scrape (9090), health (9091)
}


def _host_ip(entry) -> str | None:
    """Return the host interface a published-port entry binds to.

    ``None`` means the entry names no interface, which Docker resolves to
    every interface. Handles both the short string syntax and the long
    mapping syntax.
    """
    if isinstance(entry, dict):  # long syntax
        return entry.get("host_ip")
    text = str(entry).split("/")[0]  # drop any /tcp or /udp suffix
    parts = text.split(":")
    # "8080"            -> container only        (all interfaces)
    # "8080:80"         -> host:container        (all interfaces)
    # "127.0.0.1:80:80" -> host_ip:host:container
    return parts[0] if len(parts) >= 3 else None


def _default_profile_services() -> dict:
    """Services started by a plain ``docker compose up`` (no profile gate)."""
    compose = yaml.safe_load(COMPOSE.read_text())
    return {
        name: spec
        for name, spec in (compose.get("services") or {}).items()
        if isinstance(spec, dict) and not spec.get("profiles")
    }


def test_compose_file_is_where_this_test_thinks_it_is() -> None:
    """Guard against the gate silently passing if the file moves again.

    ``refactor/reorg-481`` moved this file from ``docker/`` to
    ``infra/docker/``. A gate that reads a path that no longer exists would
    otherwise pass by finding nothing to check.
    """
    assert COMPOSE.is_file(), f"compose file not found at {COMPOSE}"
    assert _default_profile_services(), "parsed no default-profile services"


@pytest.mark.parametrize("service", sorted(_default_profile_services()))
def test_default_service_ports_bind_loopback(service: str) -> None:
    """Every default-profile service publishes on loopback or is allowlisted."""
    spec = _default_profile_services()[service]
    published = spec.get("ports") or []
    if not published or service in REMOTE_CONSUMERS:
        pytest.skip(f"{service}: no published ports or an allowlisted remote consumer")

    exposed = [entry for entry in published if _host_ip(entry) != LOOPBACK]
    assert not exposed, (
        f"{service} publishes {exposed} on all interfaces. "
        f'Bind to loopback ("{LOOPBACK}:<host>:<container>") or, if something '
        f"off-box is meant to connect, add {service!r} to REMOTE_CONSUMERS "
        f"and say why."
    )
