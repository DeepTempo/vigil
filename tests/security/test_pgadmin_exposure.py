"""pgAdmin must not ship as an unauthenticated database console.

Issue #707. The `pgadmin` service in `infra/docker/docker-compose.yml` combined
two settings that cancelled each other out: it published `5050` on every
interface, and it set `PGADMIN_CONFIG_SERVER_MODE: 'False'`, which selects
pgAdmin's desktop mode and disables the login prompt outright. The container
logged `Configuring authentication for DESKTOP mode` and `GET /` landed
straight on `/browser/` with no credential check, which made
`PGADMIN_DEFAULT_PASSWORD` decorative rather than a gate.

That mattered more than a stray published port usually would, because pgAdmin
sits *inside* the boundary that #587 established. #587 bound Postgres to
loopback on the host, but pgAdmin reaches the database over the
`deeptempo-network` bridge by service name, so an unauthenticated console
published on `0.0.0.0` routed straight around the fix, using a default password
committed to this repo.

Two separate properties are asserted, because either one alone is insufficient:
a login prompt on an internet-facing port is still a credential-stuffing target,
and a loopback bind with no login still trusts every local process and every
other container. The port check is the one
`test_compose_port_binding.py` applies to every profile-less service; pgAdmin is
behind the opt-in `dev` profile and so falls outside that sweep, but it shares
that module's helpers rather than carrying its own copies.
"""

from __future__ import annotations

import pytest
import yaml

# The port-binding gate owns these: same compose file, same definition of
# loopback, same rule that a security gate resolves its own paths rather than
# importing application code. Duplicating them let the two drift.
from tests.security.test_compose_port_binding import (
    COMPOSE_PATH,
    LOOPBACK,
    REPO,
    _host_interface,
)

pytestmark = pytest.mark.unit

# Values pgAdmin reads as "desktop mode", i.e. no login prompt. It parses the
# variable as a string, so quoting variants all have to be caught.
DESKTOP_MODE_VALUES = frozenset({"false", "0", "no", "off"})


def _pgadmin() -> dict:
    raw = yaml.safe_load((REPO / COMPOSE_PATH).read_text(encoding="utf-8"))
    services = (raw or {}).get("services") or {}
    assert "pgadmin" in services, (
        f"no pgadmin service in {COMPOSE_PATH}. If it was removed, delete this "
        f"file; if it was renamed, update it -- do not let it pass vacuously."
    )
    return services["pgadmin"]


def _environment() -> dict[str, str]:
    """pgAdmin's env, normalised across compose's mapping and list forms."""
    env = _pgadmin().get("environment") or {}
    if isinstance(env, list):  # - KEY=value form
        parsed = {}
        for item in env:
            key, _, value = str(item).partition("=")
            parsed[key] = value
        return parsed
    return {str(k): str(v) for k, v in env.items()}  # KEY: value form


def test_pgadmin_publishes_on_loopback_only() -> None:
    wide = [
        str(m)
        for m in (_pgadmin().get("ports") or [])
        if _host_interface(m) not in LOOPBACK
    ]
    assert not wide, (
        f"pgadmin publishes {wide} on a non-loopback interface. It is a database "
        f"console with a default password and it reaches Postgres over the "
        f"compose bridge, so publishing it off-host bypasses the loopback binds "
        f"on Postgres itself (#707)."
    )


def test_pgadmin_does_not_disable_its_login() -> None:
    value = _environment().get("PGADMIN_CONFIG_SERVER_MODE")
    assert (
        value is None or value.strip().strip("'\"").lower() not in DESKTOP_MODE_VALUES
    ), (
        f"pgadmin sets PGADMIN_CONFIG_SERVER_MODE={value!r}, which selects "
        f"desktop mode and disables the login prompt entirely, making "
        f"PGADMIN_DEFAULT_PASSWORD decorative. Leave it unset so pgAdmin "
        f"defaults to server mode (#707)."
    )
