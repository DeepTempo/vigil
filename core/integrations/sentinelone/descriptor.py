"""Sentinelone integration descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

SENTINELONE = register_descriptor(
    IntegrationDescriptor(
        id="sentinelone",
        category="EDR/XDR",
        mcp_server_names=("sentinelone",),
        fields=(
            IntegrationField("api_url"),
            IntegrationField("api_token", secret=True),
        ),
    )
)
