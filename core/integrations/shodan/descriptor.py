"""Shodan integration descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

SHODAN = register_descriptor(
    IntegrationDescriptor(
        id="shodan",
        category="Threat Intelligence",
        mcp_server_names=("shodan",),
        fields=(IntegrationField("api_key", secret=True),),
    )
)
