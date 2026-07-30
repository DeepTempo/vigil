import sys
from pathlib import Path
from typing import Optional

_BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from secrets_manager import (  # noqa: E402
    SecretsManager,
    delete_secret,
    get_secrets_manager,
    set_secret,
)

__all__ = [
    "SecretsManager",
    "delete_secret",
    "get_secret",
    "get_secrets_manager",
    "set_secret",
]


def get_secret(key: str, default: Optional[str] = None) -> Optional[str]:
    # The one credential-read channel for backend, services, and daemon code.
    # Order lives in secrets_manager: encrypted store, then env, dotenv, keyring.
    return get_secrets_manager().get(key, default)
