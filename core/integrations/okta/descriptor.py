"""Okta integration descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

OKTA = register_descriptor(
    IntegrationDescriptor(
        id="okta",
        category="Identity & Access",
        mcp_server_names=("okta",),
        fields=(
            IntegrationField("domain"),
            IntegrationField("api_token", secret=True),
        ),
    )
)
