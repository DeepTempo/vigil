"""Pagerduty integration descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

PAGERDUTY = register_descriptor(
    IntegrationDescriptor(
        id="pagerduty",
        category="Communications",
        mcp_server_names=("pagerduty",),
        fields=(
            IntegrationField("api_token", secret=True),
            IntegrationField("integration_key", secret=True),
            IntegrationField("default_urgency"),
        ),
    )
)
