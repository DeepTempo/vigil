import sys
from pathlib import Path
from typing import Optional

# Repo root only: adding backend/ here makes backend/tools shadow the
# top-level tools package for every importer in the process.
_REPO_ROOT = str(Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend import secrets_manager as _secrets_manager  # noqa: E402
from backend.secrets_manager import SecretsManager, get_secrets_manager  # noqa: E402

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
    # Attributes are resolved late so the module stays a single patch seam.
    return _secrets_manager.get_secret(key, default)


def set_secret(key: str, value: str) -> bool:
    return _secrets_manager.set_secret(key, value)


def delete_secret(key: str) -> bool:
    return _secrets_manager.delete_secret(key)
