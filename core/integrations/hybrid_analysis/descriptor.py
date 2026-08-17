"""Hybrid Analysis descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

HYBRID_ANALYSIS = register_descriptor(
    IntegrationDescriptor(
        id="hybrid-analysis",
        category="Sandbox Analysis",
        mcp_server_names=("hybrid-analysis",),
        fields=(IntegrationField("api_key", secret=True),),
    )
)
