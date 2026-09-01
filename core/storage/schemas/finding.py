"""Serialization schema for the Finding model."""

from typing import Any, Optional

from core.storage.schemas.base import OptDateTime, ORMSchema


class FindingSchema(ORMSchema):
    """A security finding."""

    finding_id: Optional[str] = None
    description: Optional[str] = None
    mitre_predictions: Optional[Any] = None
    anomaly_score: Optional[float] = None
    entity_context: Optional[Any] = None
    evidence_links: Optional[Any] = None
    timestamp: OptDateTime = None
    data_source: Optional[str] = None
    external_id: Optional[str] = None
    cluster_id: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    ai_enrichment: Optional[Any] = None
    created_at: OptDateTime = None
    updated_at: OptDateTime = None
