"""Jira integration descriptor — source of truth for Jira's registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

JIRA = register_descriptor(
    IntegrationDescriptor(
        id="jira",
        category="Incident Management",
        mcp_server_names=("jira",),
        fields=(
            IntegrationField("url"),
            IntegrationField("username"),
            IntegrationField("api_token", secret=True),
            IntegrationField("project_key"),
        ),
    )
)
