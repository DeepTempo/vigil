"""Central default values for Vigil.

Import from here rather than scattering literals across the codebase.
All values are overridable via environment variables so operator deployments
can change them without code changes.
"""

import os
from typing import Any, Dict, Optional

# Fallback model ID used when no provider-specific model can be resolved
# (e.g. fresh install, DB unavailable, no ai_model_configs row).
# Operators on Ollama-only deployments should set this to their local model
# (e.g. "llama3.2:1b") so the failsafe never tries to call an Anthropic model.
DEFAULT_MODEL: str = os.getenv("DEFAULT_MODEL", "claude-sonnet-4-6")

# Anthropic models that reject the legacy extended-thinking shape
# thinking={"type": "enabled", "budget_tokens": N} with a 400 and instead
# require adaptive thinking + output_config.effort (Opus 4.7/4.8, Fable 5,
# Mythos). Matched as substrings so provider prefixes ("anthropic.") and any
# date/speed suffixes still hit.
_ADAPTIVE_THINKING_MODELS = (
    "opus-4-7",
    "opus-4-8",
    "fable-5",
    "mythos-5",
    "mythos-preview",
)


def model_requires_adaptive_thinking(model: str) -> bool:
    """True if ``model`` rejects budget_tokens thinking and needs adaptive."""
    m = (model or "").lower()
    return any(tag in m for tag in _ADAPTIVE_THINKING_MODELS)


def _thinking_budget_to_effort(budget: Optional[int]) -> str:
    """Map a legacy token budget onto an adaptive-thinking effort level."""
    if not budget or budget <= 4096:
        return "low"
    if budget <= 12000:
        return "medium"
    return "high"


def build_thinking_kwargs(model: str, budget: Optional[int]) -> Dict[str, Any]:
    """Build the messages.create/stream kwargs that enable extended thinking.

    Newer Anthropic models (Opus 4.7/4.8, Fable 5, Mythos) reject
    ``thinking={"type": "enabled", "budget_tokens": N}`` with a 400 and require
    adaptive thinking plus an ``output_config.effort`` hint instead; older
    models keep the budget-based form. ``display: "summarized"`` is set on the
    adaptive path so thinking content is still returned (the API default is
    ``omitted`` on these models, which would blank the UI's thinking view).

    Returns a dict to merge into the API kwargs — on the adaptive path it sets
    both ``thinking`` and ``output_config``.
    """
    if model_requires_adaptive_thinking(model):
        return {
            "thinking": {"type": "adaptive", "display": "summarized"},
            "output_config": {"effort": _thinking_budget_to_effort(budget)},
        }
    return {"thinking": {"type": "enabled", "budget_tokens": budget}}
