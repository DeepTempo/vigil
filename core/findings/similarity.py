"""Similarity search for findings.

Vigil does not own any embedding space. An embedding only means something
inside the model that produced it, so cosine distance between vectors from
different sources is noise. Rather than copy a source's vectors into Vigil and
pretend they are comparable, similarity is delegated back to whichever system
produced the finding — it owns the embedding, the index, and the freshest
context to rank against.

A source registers a :class:`SimilarityProvider` keyed by the finding's
``data_source``. When no provider is registered for a source, similarity is
simply unsupported for that source (empty neighbours) — the correct answer for
the many sources that never embedded anything in the first place.
"""

import logging
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class SimilarityProvider(Protocol):
    """Ranks findings similar to a seed, in the source's own vector space.

    ``neighbors`` receives the full seed finding dict (so the provider can read
    ``external_id`` — the source-native id — or any entity context it needs) and
    returns neighbour dicts already mapped back into Vigil's shape:
    ``{finding_id, similarity, cluster_id, severity, data_source, anomaly_score}``.
    """

    def neighbors(
        self, finding: Dict[str, Any], limit: int
    ) -> List[Dict[str, Any]]: ...


_PROVIDERS: Dict[str, SimilarityProvider] = {}


def register_provider(data_source: str, provider: SimilarityProvider) -> None:
    """Register the similarity backend for findings of ``data_source``."""
    _PROVIDERS[data_source] = provider


def get_provider(data_source: Optional[str]) -> Optional[SimilarityProvider]:
    if not data_source:
        return None
    return _PROVIDERS.get(data_source)


def similar_findings(data, finding_id: str, limit: int = 10) -> Dict[str, Any]:
    """Findings similar to ``finding_id``, resolved via the seed's source.

    ``data`` is the data service used to resolve the seed finding. Returns
    ``{"seed_finding", "neighbors"}``; ``neighbors`` is empty (with
    ``unsupported_source`` set) when the seed's source has no registered
    provider, and ``{"error": ...}`` when the seed cannot be found.
    """
    seed = data.get_finding(finding_id)
    if not seed:
        return {"error": f"Finding {finding_id} not found"}

    source = seed.get("data_source")
    provider = get_provider(source)
    if provider is None:
        return {
            "seed_finding": finding_id,
            "neighbors": [],
            "unsupported_source": source,
        }

    try:
        neighbors = provider.neighbors(seed, limit)
    except Exception as e:
        logger.error(
            f"Similarity provider for source '{source}' failed on " f"{finding_id}: {e}"
        )
        return {"seed_finding": finding_id, "neighbors": [], "error": str(e)}

    return {"seed_finding": finding_id, "neighbors": neighbors[:limit]}
