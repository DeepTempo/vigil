"""Microsoft Defender descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

MICROSOFT_DEFENDER = register_descriptor(
    IntegrationDescriptor(
        id="microsoft-defender",
        category="EDR",
        mcp_server_names=("microsoft-defender",),
        fields=(
            IntegrationField("tenant_id"),
            IntegrationField("client_id"),
            IntegrationField("client_secret", secret=True),
        ),
    )
)
