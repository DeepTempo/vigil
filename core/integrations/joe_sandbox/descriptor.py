"""Joe Sandbox integration descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

JOE_SANDBOX = register_descriptor(
    IntegrationDescriptor(
        id="joe-sandbox",
        category="Sandbox Analysis",
        mcp_server_names=("joe-sandbox",),
        fields=(
            IntegrationField("api_key", secret=True),
            IntegrationField("api_url"),
        ),
    )
)
