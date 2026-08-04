"""Single source of truth for the mempalace palace data directory (#129).

Before this module, three places picked a default for the palace path
and two of them disagreed:

  mcp-config.json             → ~/.vigil/mempalace/palace
  daemon/orchestrator.py      → ~/.mempalace/palace         (diverged)
  services/claude_service.py  → ad-hoc detection

The split-brain meant investigation snapshots written by the daemon
ended up in a different palace than the one the MCP server was
reading from. This module exposes one helper, ``get_palace_path()``,
that every caller funnels through, so the default can't drift again.

Override with ``MEMPALACE_PALACE_PATH`` when the operator wants the
palace somewhere else (shared NAS, different user, etc.). The
directory is created on first access so callers don't each need to
``mkdir -p``.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# Matches mcp-config.json's default for the mempalace server. Keep in
# sync with that file — both point at the same directory so the MCP
# server, daemon, and ClaudeService-side integration all see the same
# palace without any env var set.
_DEFAULT_PALACE = Path.home() / ".vigil" / "mempalace" / "palace"


def get_palace_path(*, ensure_exists: bool = True) -> Path:
    """Return the resolved mempalace palace path.

    Reads ``MEMPALACE_PALACE_PATH`` from the environment, falling back
    to ``~/.vigil/mempalace/palace``. When ``ensure_exists=True``
    (default) the directory is created if missing — safe to call from
    hot paths.
    """
    raw = os.environ.get("MEMPALACE_PALACE_PATH")
    palace = Path(raw).expanduser() if raw else _DEFAULT_PALACE
    if ensure_exists:
        try:
            palace.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            # Don't let a filesystem hiccup kill the caller — the
            # palace being missing is a degraded-but-survivable mode.
            logger.warning("Could not create palace dir %s: %s", palace, e)
    return palace


def get_closed_cases_dir(*, ensure_exists: bool = True) -> Path:
    """Path to the investigations/closed-cases subdirectory.

    Used by ``daemon/orchestrator.py`` to persist investigation
    snapshots as JSON files alongside the ChromaDB collection.
    """
    path = (
        get_palace_path(ensure_exists=ensure_exists) / "investigations" / "closed-cases"
    )
    if ensure_exists:
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.warning("Could not create closed-cases dir %s: %s", path, e)
    return path
