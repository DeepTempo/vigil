"""Microsoft Teams descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

MICROSOFT_TEAMS = register_descriptor(
    IntegrationDescriptor(
        id="microsoft-teams",
        category="Communications",
        mcp_server_names=("microsoft-teams",),
        fields=(
            IntegrationField("webhook_url", secret=True),
            IntegrationField("tenant_id"),
        ),
    )
)
