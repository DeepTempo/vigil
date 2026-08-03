"""The ``enrich()`` seam: resolve provider → dispatch → parse → stamp → persist.

Extracted from ``backend/api/findings.py``'s 333-line
``get_or_generate_enrichment`` handler (#470) so ingestion, the daemon and
agents can reuse the flow instead of it being reachable only over HTTP.

Behaviour is preserved exactly as it was in the handler, including two things
that are known-imperfect and deliberately *not* fixed here:

**The dispatch asymmetry.** Anthropic goes through the sync ``ClaudeService``
on a threadpool with no retry; every other provider goes through
``LLMRouter.dispatch`` wrapped in a retry loop with local-Bifrost recovery.
That is existing behaviour, not a design position — unifying it while moving
code would make any regression impossible to bisect. See #470's notes.

**The ``ai_enrichment`` write is a full replace, and it has a second writer.**
``daemon/processor.py`` writes triage keys (``ai_triage``, ``enrichment``,
``enriched_at``, ``triage_confidence``, ``category``, ``recommended_action``,
``triage_reasoning``) into the same JSONB column; this module writes analysis
keys (``threat_summary``, ``potential_impact``, ``recommended_actions``, …).
The two key sets do not overlap, so today:

1. the API's cache check can return a daemon triage payload labelled as an
   analysis ``enrichment``, and the UI reads ``undefined`` off it;
2. persisting here wipes any daemon triage on the same finding, because
   ``update_finding(..., ai_enrichment=...)`` replaces the whole value; and
3. the finding then falls out of the daemon's ``ai_enrichment IS NULL``
   backfill permanently.

Fixing that is a JSONB schema change with a read-side compatibility shim, so
it is a separate change. What this module does provide is the seam for it:
``persist=False`` returns the payload and lets the caller compose its own
write, so the merge policy can live in one place later without reopening this
module.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from services.findings.enrichment.errors import (
    FindingNotFound,
    NoProviderConfigured,
    ProviderUnavailable,
)
from services.findings.enrichment.parse import parse_enrichment
from services.findings.enrichment.prompt import build_prompt, summarize_finding

logger = logging.getLogger(__name__)

# Bounded separately per path: the enrichment JSON schema is large, so a tight
# cap truncates it — but local models are slow per token, so they get a
# tighter bound than the cloud path while still leaving room for the object.
ANTHROPIC_MAX_TOKENS = 4096
LOCAL_MAX_TOKENS = 1400

LOCAL_SYSTEM_PROMPT = (
    "You are a cybersecurity analyst. Respond only with valid "
    "JSON matching the requested enrichment schema. Keep the "
    "response concise and do not include chain-of-thought."
)

_data_service: Any = None


def _default_data_service() -> Any:
    """Lazily build this module's own ``DatabaseDataService``.

    Constructing one runs ``init_database``, so it must not happen at import
    time: callers passing ``persist=False`` (or their own ``data_service``)
    should never pay for a connection they don't use.
    """
    global _data_service
    if _data_service is None:
        from services.database_data_service import DatabaseDataService

        _data_service = DatabaseDataService()
    return _data_service


def _resolve_provider(component: str) -> Tuple[Any, str, Any]:
    """Resolve ``component`` to ``(provider_spec, model_id, claude_service)``.

    ``claude_service`` is None for every non-Anthropic provider — only the
    Anthropic path uses the SDK client, and only that path needs the API-key
    precheck (``has_api_key`` is Anthropic-specific by design).

    Raises:
        NoProviderConfigured: nothing resolved, or no Anthropic API key.
        ProviderUnavailable: the resolved provider id has no spec row.
    """
    from services.llm_router import get_provider_spec
    from services.model_registry import get_registry

    resolved_model = get_registry().resolve_model_for_component(component)
    if not resolved_model:
        raise NoProviderConfigured(
            f"No LLM provider is configured for component '{component}'"
        )

    provider_id, model_id = resolved_model
    provider = get_provider_spec(provider_id)
    if provider is None:
        raise ProviderUnavailable(f"Configured provider '{provider_id}' is unavailable")

    claude_service = None
    if provider.provider_type == "anthropic":
        from services.claude_service import ClaudeService

        claude_service = ClaudeService(use_backend_tools=True, use_mcp_tools=False)
        if not claude_service.has_api_key():
            raise NoProviderConfigured(
                f"Anthropic provider '{provider_id}' has no resolvable API key"
            )

    return provider, model_id, claude_service


async def _dispatch(
    *,
    provider: Any,
    model_id: str,
    prompt: str,
    claude_service: Any,
    finding_id: str,
) -> Optional[str]:
    """Send ``prompt`` to ``provider`` and return the raw text response.

    The two paths are asymmetric — see the module docstring. Preserved as-is.
    """
    loop = asyncio.get_event_loop()
    if provider.provider_type == "anthropic":
        # No retry here: the cloud path has never had one.
        return await loop.run_in_executor(
            None,
            lambda: claude_service.chat(
                message=prompt,
                model=model_id,
                max_tokens=ANTHROPIC_MAX_TOKENS,
            ),
        )

    dispatch_args = {
        "provider": provider,
        "messages": [{"role": "user", "content": f"/no_think\n{prompt}"}],
        "system_prompt": LOCAL_SYSTEM_PROMPT,
        "model": model_id,
        "max_tokens": LOCAL_MAX_TOKENS,
    }
    from services.llm_router import LLMRouter
    from services.local_ai_recovery import (
        is_gateway_connection_error,
        local_bifrost_recovery_enabled,
        local_bifrost_recovery_retry_limit,
        recover_local_bifrost,
    )

    retry_limit = local_bifrost_recovery_retry_limit()
    for attempt in range(retry_limit + 1):
        try:
            result = await LLMRouter().dispatch(**dispatch_args)
            break
        except Exception as dispatch_error:
            eligible = (
                provider.provider_type == "ollama"
                and local_bifrost_recovery_enabled()
                and is_gateway_connection_error(dispatch_error)
            )
            if not eligible or attempt >= retry_limit:
                raise

            recovery = await recover_local_bifrost()
            if not recovery.ready:
                logger.warning(
                    "Local Bifrost recovery for %s failed: %s",
                    finding_id,
                    recovery.detail,
                )
                raise
            logger.info(
                "Local Bifrost recovery for %s: %s; retrying enrichment (%s/%s)",
                finding_id,
                recovery.detail,
                attempt + 1,
                retry_limit,
            )
    return result.get("content", "")


async def _persist(
    finding_id: str, enrichment: Dict[str, Any], data_service: Any
) -> bool:
    """Write ``enrichment`` to the finding's ``ai_enrichment`` column.

    A **full replace**, not a merge — see the module docstring for the writer
    collision this carries forward. A failed write is logged and swallowed:
    the caller still gets the payload it paid a provider call for.

    The write goes through ``asyncio.to_thread`` because the data layer is
    synchronous SQLAlchemy and ``enrich()`` is called from the event loop.
    The pre-extraction handler offloaded this same call (#518, refs #461);
    moving it into a plain ``def`` here would have put it back on the loop.
    """
    service = data_service if data_service is not None else _default_data_service()
    success = await asyncio.to_thread(
        service.update_finding, finding_id, ai_enrichment=enrichment
    )
    if not success:
        logger.error("Failed to save enrichment for %s", finding_id)
    else:
        logger.info("Successfully generated and cached enrichment for %s", finding_id)
    return bool(success)


async def enrich(
    finding: Dict[str, Any],
    *,
    component: str = "reporting",
    persist: bool = True,
    data_service: Any = None,
) -> Dict[str, Any]:
    """Generate AI enrichment for ``finding``. Returns the enrichment payload.

    Takes a finding *dict*, not an id: the fetch (and its 404) stays with the
    caller, so this module needs no database access for reads, and the daemon —
    which already holds finding dicts — doesn't re-read them.

    Does **not** do a cache check. Whether an existing ``ai_enrichment`` value
    counts as a usable cache hit is caller policy (the HTTP handler has a
    ``force_regenerate`` query param; see also the writer collision noted in
    the module docstring).

    Args:
        finding: The finding to enrich.
        component: ``ai_model_configs`` component whose model assignment to
            use. The HTTP handler uses ``"reporting"``.
        persist: Write the result to the finding's ``ai_enrichment`` column.
            Pass False to compose your own write.
        data_service: Persistence target; defaults to a lazily-built
            ``DatabaseDataService``. Pass an existing instance to avoid a
            second one.

    Raises:
        FindingNotFound: ``finding`` is empty.
        NoProviderConfigured: no usable provider for ``component``.
        ProviderUnavailable: resolved provider id has no spec row.
        EmptyProviderResponse: the provider returned nothing.
    """
    if not finding:
        raise FindingNotFound("Finding not found")

    # Resolve before shaping input, so an unconfigured provider still reports
    # NoProviderConfigured rather than whatever a malformed finding raises.
    provider, model_id, claude_service = _resolve_provider(component)

    summary = summarize_finding(finding)
    finding_id = summary.finding_id
    prompt = build_prompt(summary)

    logger.info(
        "Generating AI enrichment for %s via %s/%s",
        finding_id,
        provider.provider_id,
        model_id,
    )
    response = await _dispatch(
        provider=provider,
        model_id=model_id,
        prompt=prompt,
        claude_service=claude_service,
        finding_id=finding_id,
    )

    enrichment = parse_enrichment(response, severity=summary.severity)

    # Keep the provider's original response even when it parsed cleanly.
    # Analysts can compare the rendered fields against the local model's
    # exact output without having to regenerate the enrichment.
    enrichment["raw_response"] = response
    enrichment["generated_at"] = datetime.utcnow().isoformat() + "Z"
    enrichment["model"] = model_id
    enrichment["provider_id"] = provider.provider_id
    enrichment["provider_type"] = provider.provider_type

    if persist:
        await _persist(finding_id, enrichment, data_service)

    return enrichment
