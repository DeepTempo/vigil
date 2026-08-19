"""Azure Ad integration descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

AZURE_AD = register_descriptor(
    IntegrationDescriptor(
        id="azure-ad",
        category="Identity & Access",
        mcp_server_names=("azure-ad",),
        fields=(
            IntegrationField("tenant_id"),
            IntegrationField("client_id"),
            IntegrationField("client_secret", secret=True),
        ),
    )
)
