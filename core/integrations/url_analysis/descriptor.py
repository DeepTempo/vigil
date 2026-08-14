"""Url Analysis integration descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

URL_ANALYSIS = register_descriptor(
    IntegrationDescriptor(
        id="url-analysis",
        category="Threat Intelligence",
        mcp_server_names=("url-analysis",),
        fields=(IntegrationField("service"),),
    )
)
