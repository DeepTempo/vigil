"""Database isolation for DB-backed unit tests (#747).

A unit test that writes to the database used to write to whatever
``DATABASE_URL`` pointed at, which for a developer is the database their own
console reads. ``TestApprovalQueue`` left three pending containment proposals
behind per run and 93 had piled up in the approvals queue before anyone
connected the two.

Per-test cleanup would fix the tests that exist; provisioning a throwaway
database fixes the ones nobody has audited yet. Any unit test marked
``database`` or ``external_service`` is handed a fresh ``vigil_test_<pid>``
built from the ORM models, and the whole database is dropped afterwards, so a
test that forgets to tidy up cannot reach anyone's data.

Deliberately not a skip when the server is unreachable: the DB-backed CI job
exists to run these, and a fixture that skipped its way to green would retire
that gate silently. A missing Postgres is an error here.
"""

import os

import pytest
from sqlalchemy import create_engine, text

# Markers that mean "this test talks to PostgreSQL". `external_service` is the
# marker CI's DB-backed unit job selects on (`-m external_service`), and
# `database` is the descriptive one; either earns an isolated database.
_DB_MARKERS = ("database", "external_service")

_EXTENSIONS = (
    "CREATE EXTENSION IF NOT EXISTS vector",
    "CREATE EXTENSION IF NOT EXISTS pg_trgm",
    'CREATE EXTENSION IF NOT EXISTS "uuid-ossp"',
)


def _quote_ident(name: str) -> str:
    """Quote a database name for DDL, which cannot take a bind parameter."""
    return '"' + name.replace('"', '""') + '"'


@pytest.fixture(scope="session")
def throwaway_database():
    """Create a database for this pytest process, retarget at it, drop it after.

    Session-scoped: provisioning costs a `create_all` and the tests that use it
    are already ordered arbitrarily, so per-test databases would buy isolation
    the residue problem does not need.
    """
    from core.storage.connection import DatabaseConfig, get_db_manager

    # Whatever the environment points at — the developer's dev database, or the
    # test database CI provisions. Used only as the maintenance connection.
    origin = DatabaseConfig()
    name = f"vigil_test_{os.getpid()}"
    ident = _quote_ident(name)

    admin = create_engine(origin.get_database_url(), isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            # A previous run killed mid-session can leave the name behind; the
            # pid makes a collision with a *live* run impossible.
            conn.execute(text(f"DROP DATABASE IF EXISTS {ident} WITH (FORCE)"))
            conn.execute(text(f"CREATE DATABASE {ident}"))
    finally:
        admin.dispose()

    manager = get_db_manager()
    target = DatabaseConfig()
    target.database = name
    manager.retarget(target)

    with manager.engine.connect() as conn:
        for statement in _EXTENSIONS:
            conn.execute(text(statement))
        conn.commit()
    manager.create_tables()

    try:
        yield name
    finally:
        # Point the manager back at the origin first: that disposes the engine
        # holding connections to the database about to be dropped.
        manager.retarget(origin)
        admin = create_engine(origin.get_database_url(), isolation_level="AUTOCOMMIT")
        try:
            with admin.connect() as conn:
                conn.execute(text(f"DROP DATABASE IF EXISTS {ident} WITH (FORCE)"))
        finally:
            admin.dispose()


@pytest.fixture(autouse=True)
def _isolate_database(request):
    """Hand every DB-marked unit test the throwaway database.

    Autouse so it covers tests that have not been audited, but lazy: a test
    without a DB marker never requests the fixture, so the ~1600 unit tests
    that need no database still run with no server present.
    """
    if any(request.node.get_closest_marker(m) for m in _DB_MARKERS):
        request.getfixturevalue("throwaway_database")
