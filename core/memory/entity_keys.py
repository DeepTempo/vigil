"""Entity Keys, and the one rule for making one.

Only Python writes an Entity Key. The harness extracts candidates and hands over
a type and a value; the key they join on is minted here, so a stored key and a
queried key cannot be normalised by two rules that drift.

The rule is ``defang`` then case-fold, mirroring
``services/agent/workflows/hunt/entities.ts``. The exception is the half that
breaks silently: an ARN's resource part and an AWS key id are case-significant,
so folding them makes two principals one key — and the join still returns rows,
just the wrong ones.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from core.memory.recall_contract import KEY_CASE_SENSITIVE_TYPES

# Threat intel writes addresses defanged, and threat_intel is a worker whose
# output feeds this, so normalising first is cheaper than carrying defanged
# variants of every key.
_DEFANG: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
    (re.compile(r"\bh(?:xx)p", re.IGNORECASE), "http"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[at\]", re.IGNORECASE), "@"),
)


def defang(text: str) -> str:
    for pattern, replacement in _DEFANG:
        text = pattern.sub(replacement, text)
    return text


def entity_key(entity_type: str, value: str) -> str:
    """Return ``type:value``, or ``""`` when either half is absent.

    An empty key is dropped by the caller rather than raising: one unusable
    candidate in a payload must not fail the investigation it arrived in.
    """
    kind = (entity_type or "").strip().lower()
    text = defang((value or "").strip())
    if not kind or not text:
        return ""
    if kind not in KEY_CASE_SENSITIVE_TYPES:
        text = text.lower()
    return f"{kind}:{text}"


def entity_keys(entities: object) -> List[str]:
    """Keys for a list of ``{"type", "value"}`` candidates, deduped in order.

    Order is kept because a Verdict's subjects read back to a human, and an
    unusable candidate is skipped rather than stored as a partial key.
    """
    keys: List[str] = []
    seen = set()
    for entity in entities if isinstance(entities, list) else []:
        if not isinstance(entity, dict):
            continue
        key = entity_key(str(entity.get("type", "")), str(entity.get("value", "")))
        if key and key not in seen:
            seen.add(key)
            keys.append(key)
    return keys
