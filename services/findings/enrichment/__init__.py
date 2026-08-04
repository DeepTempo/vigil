"""Finding AI-enrichment: prompt building, provider dispatch, response parsing.

Extracted from the 333-line ``get_or_generate_enrichment`` handler in
``backend/api/findings.py`` so the flow is reachable from more than one HTTP
path — ingestion, the daemon and agents can call the same seam (#470).

The single entry point is :func:`enrich`::

    from services.findings.enrichment import enrich, EnrichmentError

    try:
        payload = await enrich(finding)             # persists by default
    except EnrichmentError as exc:
        ...

Callers that want to compose their own database write pass ``persist=False``.
Failures are domain exceptions (see :mod:`~services.findings.enrichment.errors`),
never ``HTTPException`` — translation to status codes belongs to the HTTP
boundary in ``backend/api/findings.py``.
"""

from services.findings.enrichment.errors import (
    EmptyProviderResponse,
    EnrichmentError,
    FindingNotFound,
    NoProviderConfigured,
    ProviderUnavailable,
    UnidentifiableFinding,
)
from services.findings.enrichment.parse import extract_json_block, parse_enrichment
from services.findings.enrichment.prompt import (
    FindingSummary,
    build_entity_string,
    build_prompt,
    build_techniques_string,
    summarize_finding,
)
from services.findings.enrichment.service import enrich

__all__ = [
    "EmptyProviderResponse",
    "EnrichmentError",
    "FindingNotFound",
    "FindingSummary",
    "NoProviderConfigured",
    "ProviderUnavailable",
    "UnidentifiableFinding",
    "build_entity_string",
    "build_prompt",
    "build_techniques_string",
    "enrich",
    "extract_json_block",
    "parse_enrichment",
    "summarize_finding",
]
