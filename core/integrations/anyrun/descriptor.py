"""Anyrun integration descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

ANYRUN = register_descriptor(
    IntegrationDescriptor(
        id="anyrun",
        category="Sandbox Analysis",
        mcp_server_names=("anyrun",),
        fields=(IntegrationField("api_key", secret=True),),
    )
)
