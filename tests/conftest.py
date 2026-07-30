# Defaults DEV_MODE=true for the whole suite before any test module is imported:
# several API tests import routers at module load, which transitively imports
# auth_service, which raises at import time if DEV_MODE is false and
# JWT_SECRET_KEY is unset. setdefault leaves an explicitly-set DEV_MODE alone.

import os

os.environ.setdefault("DEV_MODE", "true")

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_settings_cache():
    # get_settings() is lru_cached, so tests that monkeypatch env need the cache
    # dropped on both sides of the test to avoid leaking a stale Settings.
    # Imported lazily: `core` pulls in the app dependencies via core/__init__, and
    # collecting a pure-AST test must not require them.
    from core.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
