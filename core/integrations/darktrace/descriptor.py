"""Darktrace integration descriptor — source of truth for registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    register_descriptor,
)

DARKTRACE = register_descriptor(
    IntegrationDescriptor(
        id="darktrace",
        category="Network Security",
    )
)
