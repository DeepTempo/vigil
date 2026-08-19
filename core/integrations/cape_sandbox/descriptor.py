"""Cape Sandbox integration descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

CAPE_SANDBOX = register_descriptor(
    IntegrationDescriptor(
        id="cape-sandbox",
        category="Sandbox Analysis",
        mcp_server_names=("cape-sandbox",),
        fields=(
            IntegrationField("url"),
            IntegrationField("api_key", secret=True),
        ),
    )
)
