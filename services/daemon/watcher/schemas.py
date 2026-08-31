"""Typed output contract for the Watcher's Hypothesizer.

The Hypothesizer reads an alert (a normalized finding dict) and produces the
artifact a human authors in the console today: the hypotheses to test plus the
scope and context a hunt needs to run. This module defines only the *shape* of
that answer — the blanks the Hypothesizer must fill and the rules a valid answer
obeys. No logic, no model call lives here.

Only ``hypotheses`` (>=1) and ``narrative`` are required. Techniques and data
domains are *inferred* by the Hypothesizer and may legitimately be empty — a
source like Splunk arrives with ``mitre_predictions={}``, and an empty list just
means the hunt does not narrow its worker search on that axis. Nothing here
assumes the input finding is richly populated.
"""

from typing import Dict, List

from pydantic import BaseModel, Field, field_validator


class WatcherHypothesisSet(BaseModel):
    """What the Hypothesizer hands to the spec builder for one alert."""

    hypotheses: List[str] = Field(
        ...,
        min_length=1,
        description=(
            "Concrete, testable attacker-intent claims derived from the alert. "
            "At least one is required; a hunt with nothing real to test is refused."
        ),
    )
    narrative: str = Field(
        ...,
        description=(
            "One or two sentences of context: what the alert saw and why it is "
            "worth a hunt. Not taken from the alert — written by the Hypothesizer."
        ),
    )
    attack_techniques: List[str] = Field(
        default_factory=list,
        description=(
            "MITRE technique IDs (e.g. 'T1071.004'). Taken from the finding's "
            "mitre_predictions when present, otherwise inferred; empty is valid."
        ),
    )
    data_domains: List[str] = Field(
        default_factory=list,
        description=(
            "Where to look: dns, network, endpoint, auth, etc. Inferred from the "
            "finding's data_source and populated entity buckets; empty is valid."
        ),
    )
    scope: Dict[str, List[str]] = Field(
        default_factory=dict,
        description=(
            "Entities in play, mirroring the finding's entity_context "
            "(src_ips, dest_ips, hostnames, usernames). May be partial."
        ),
    )
    source_finding_id: str = Field(
        ...,
        description="The finding_id this hypothesis set was derived from.",
    )

    @field_validator("hypotheses")
    @classmethod
    def _no_blank_hypotheses(cls, value: List[str]) -> List[str]:
        cleaned = [h.strip() for h in value if h and h.strip()]
        if not cleaned:
            raise ValueError("at least one non-empty hypothesis is required")
        return cleaned

    @field_validator("narrative")
    @classmethod
    def _narrative_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("narrative must not be empty")
        return value.strip()
