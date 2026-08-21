"""Naive-UTC clock helper.

SQLAlchemy columns in this codebase are naive ``DateTime`` (no timezone).
``datetime.utcnow()`` is deprecated in 3.12+, but ``datetime.now(timezone.utc)``
is aware and TypeErrors when compared to those naive column values. This helper
is the drop-in: same naive UTC wall-clock as ``utcnow()``, without the
deprecation.
"""

from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return the current UTC time as a naive datetime."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
