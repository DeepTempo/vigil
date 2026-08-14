"""Virustotal integration descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

VIRUSTOTAL = register_descriptor(
    IntegrationDescriptor(
        id="virustotal",
        category="Threat Intelligence",
        mcp_server_names=("virustotal",),
        fields=(IntegrationField("api_key", secret=True),),
    )
)
