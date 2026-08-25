"""Alienvault Otx descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

ALIENVAULT_OTX = register_descriptor(
    IntegrationDescriptor(
        id="alienvault-otx",
        category="Threat Intelligence",
        mcp_server_names=("alienvault-otx",),
        fields=(IntegrationField("api_key", secret=True),),
    )
)
