"""Domain exceptions for finding enrichment.

Status codes the HTTP boundary maps (backend/api/findings.py:373–392) these to:

===========================  ======  ==================================
Exception                    Status  Detail
===========================  ======  ==================================
``FindingNotFound``          404     ``"Finding not found"``
``UnidentifiableFinding``    500     ``"Failed to generate …: {exc}"``
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


class UnidentifiableFinding(EnrichmentError):
    """The finding to enrich carries no id, so the result can't be persisted.

    ``update_finding("")`` matches no row and reports failure, which
    ``_persist`` only logs — so without this guard a caller that hands over a
    dict lacking ``finding_id`` silently loses the enrichment it just paid a
    provider call for. Unreachable over HTTP (the path param is always
    non-empty); it exists for the daemon/ingestion callers that pass their own
    dicts.
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
