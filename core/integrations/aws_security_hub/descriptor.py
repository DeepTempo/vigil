"""AWS Security Hub descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

AWS_SECURITY_HUB = register_descriptor(
    IntegrationDescriptor(
        id="aws-security-hub",
        category="Cloud Security",
        # The mcp-config key is "aws-security"; the Integration Id is not.
        mcp_server_names=("aws-security",),
        fields=(
            IntegrationField("access_key_id"),
            IntegrationField("secret_access_key", secret=True),
            IntegrationField("region"),
        ),
    )
)
