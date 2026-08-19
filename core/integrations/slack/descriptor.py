"""Slack integration descriptor — source of truth for Slack's registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

SLACK = register_descriptor(
    IntegrationDescriptor(
        id="slack",
        category="Communications",
        mcp_server_names=("slack",),
        fields=(
            IntegrationField("bot_token", secret=True),
            IntegrationField("default_channel"),
        ),
    )
)
