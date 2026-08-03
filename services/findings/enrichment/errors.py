"""Domain exceptions for finding enrichment.

The enrichment flow used to live inline in ``backend/api/findings.py`` and
raised ``HTTPException`` straight from the business logic, which made it
unusable from the daemon or from ingestion — neither speaks HTTP. This module
raises these instead, and ``backend/api/findings.py`` owns the single
``EnrichmentError`` → status-code translation (#470).

Status codes the HTTP boundary maps these to:

===========================  ======  ==================================
Exception                    Status  Detail
===========================  ======  ==================================
``FindingNotFound``          404     ``"Finding not found"``
``NoProviderConfigured``     503     ``claude.NO_PROVIDER_DETAIL``
``ProviderUnavailable``      503     ``str(exc)``
``EmptyProviderResponse``    500     ``"Failed to generate …: {exc}"``
===========================  ======  ==================================
"""


class EnrichmentError(Exception):
    """Base class for every finding-enrichment failure."""


class FindingNotFound(EnrichmentError):
    """The finding to enrich does not exist.

    ``enrich()`` takes a finding *dict*, so callers normally fetch (and 404)
    themselves; this guards the case where a caller hands over ``None``
    without checking, so it surfaces as a domain error rather than an
    ``AttributeError`` from deep inside prompt building.
    """


class NoProviderConfigured(EnrichmentError):
    """No usable LLM provider is configured for the requested component.

    Covers both "the registry resolved nothing" and "the resolved Anthropic
    provider has no API key" — the HTTP boundary answers both with the
    canonical ``NO_PROVIDER_DETAIL`` payload the chat drawer matches on to
    render a "Configure a provider" CTA.
    """


class ProviderUnavailable(EnrichmentError):
    """The registry resolved a provider id that has no provider spec row."""


class EmptyProviderResponse(EnrichmentError):
    """The provider returned no content to parse."""
