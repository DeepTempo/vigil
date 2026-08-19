"""Cloudflare integration descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

CLOUDFLARE = register_descriptor(
    IntegrationDescriptor(
        id="cloudflare",
        category="Network Security",
        mcp_server_names=("cloudflare",),
        fields=(
            IntegrationField("api_token", secret=True),
            IntegrationField("account_id"),
            IntegrationField("zone_id"),
        ),
    )
)
