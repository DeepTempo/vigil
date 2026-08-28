"""The source-to-Source-Tier map (#728).

Ranking needs two telemetry sources agreeing to outweigh two feeds agreeing,
and needs some sources not to count as evidence at all. Memory owns this map
and stamps the tier onto the row at write time rather than joining at read
time, so an integration removed or recategorised later cannot retroactively
change how a past Verdict was corroborated.

The map is keyed twice, because the two investigation kinds name sources in
different vocabularies. A hunt names a telemetry domain, narrowed to the
playbook's ``data_domains`` by ``attributeSource``. A Case names the
``data_source`` of the Findings it groups, which is a vendor pipeline. Both
land in memory's own ``source_system`` column, so ``source_tier`` takes the
investigation kind to know which vocabulary it is reading.
"""

import logging
from enum import Enum
from typing import Dict, Set

logger = logging.getLogger(__name__)


class SourceTier(str, Enum):
    """What a source *is*, as distinct from who concluded (**Trust**)."""

    TELEMETRY = "telemetry"
    FEED = "feed"
    NOT_EVIDENCE = "not_evidence"


class InvestigationKind(str, Enum):
    """Which vocabulary a source name is drawn from."""

    HUNT = "hunt"
    CASE = "case"


DEFAULT_TIER = SourceTier.FEED

# Reference and harness-internal names. A rulebook cited as corroboration is a
# run treating a lookup as an observation; the critic arguing with itself, an
# operator declaring a blind spot and the dispatcher recording a failed tool
# call are none of them a second look at the estate. `not_evidence` on a Verdict
# is a defect rather than a weak row, so these exist to make it visible.
#
# The harness-internal three reach the ledger under their own names because
# `attributeSource` collapses only `provenance === "worker"`, and each of them
# is appended under a different provenance. The two reference servers cannot
# arrive on either path today — they write no findings, and a worker naming one
# collapses to `undeclared` first. They are listed because AC 4 asks for the
# guard, and a guard is meant to have no hits in healthy data.
_NOT_EVIDENCE: Set[str] = {
    "attack-layer",
    "security-detections",
    "critic",
    "operator",
    "dispatcher",
}

# Detonation is a real observation, but of an artifact rather than of our
# estate, so two sandboxes agreeing is not two independent looks at it.
_SANDBOX: Set[str] = {
    "cape-sandbox",
    "joe-sandbox",
}

# The nine values present in `findings.data_source`, enumerated against live
# data on 2026-08-28: `loglm` carries 98% of rows and the rest are the ingest
# and demo pipeline labels behind it. All nine observe our own estate. The two
# ingest fallbacks below are reachable in code but absent from that census.
_CASE_TIERS: Dict[str, SourceTier] = {
    "loglm": SourceTier.TELEMETRY,
    "firewall": SourceTier.TELEMETRY,
    "proxy": SourceTier.TELEMETRY,
    "flow": SourceTier.TELEMETRY,
    "edr": SourceTier.TELEMETRY,
    "dns": SourceTier.TELEMETRY,
    "email": SourceTier.TELEMETRY,
    "endpoint": SourceTier.TELEMETRY,
    "siem": SourceTier.TELEMETRY,
    # Ingest fallbacks, used when a row declared no source of its own. Known
    # values, deliberately left at the default: an import of unstated
    # provenance is exactly what the conservative direction is for, and naming
    # them here keeps them out of the unknown-source log.
    "imported": SourceTier.FEED,
    "csv_import": SourceTier.FEED,
}

# Two sets of `data_domains`. `network`/`authentication`/`endpoint` are the
# shipped threat-hunt WORKFLOW.md's; `cloud_audit`/`identity`/`endpoint_process`
# appear in no repo file but are what every live hunt declared as of
# 2026-08-28, so a spec is reaching the runtime from outside the tree. A worker
# label outside its own playbook's list never arrives here under that name —
# `attributeSource` collapses it to `undeclared` first.
_HUNT_TIERS: Dict[str, SourceTier] = {
    "network": SourceTier.TELEMETRY,
    "authentication": SourceTier.TELEMETRY,
    "endpoint": SourceTier.TELEMETRY,
    "cloud_audit": SourceTier.TELEMETRY,
    "identity": SourceTier.TELEMETRY,
    "endpoint_process": SourceTier.TELEMETRY,
    # The collapse already decided this source could not be vouched for, so it
    # takes the default rather than the tier of the domains around it.
    "undeclared": SourceTier.FEED,
}

_TIERS_BY_KIND: Dict[InvestigationKind, Dict[str, SourceTier]] = {
    InvestigationKind.CASE: _CASE_TIERS,
    InvestigationKind.HUNT: _HUNT_TIERS,
}


def resolve_source_tier(
    source_system: str, investigation_kind: InvestigationKind
) -> SourceTier:
    """Return the **Source Tier** of ``source_system`` in its own vocabulary.

    An unknown source resolves to :data:`DEFAULT_TIER` and is logged rather
    than raising: a source memory has never seen must not stop an
    investigation being distilled, and grading it a feed understates its
    corroborating weight instead of overstating it.

    This makes a `not_evidence` source visible, not impossible. User story 38
    wants it rejected outright on a Verdict, which is a write-path decision and
    belongs to `distil` (#731); a map that raised here would fail the whole
    investigation over one bad citation.
    """
    name = (source_system or "").strip().lower()
    if not name:
        logger.warning(
            "Source Tier: empty source_system on a %s, defaulting to %s",
            investigation_kind.value,
            DEFAULT_TIER.value,
        )
        return DEFAULT_TIER

    if name in _NOT_EVIDENCE:
        return SourceTier.NOT_EVIDENCE

    if name in _SANDBOX:
        return SourceTier.FEED

    tier = _TIERS_BY_KIND[investigation_kind].get(name)
    if tier is None:
        logger.warning(
            "Source Tier: unknown source %r on a %s, defaulting to %s",
            source_system,
            investigation_kind.value,
            DEFAULT_TIER.value,
        )
        return DEFAULT_TIER

    return tier
