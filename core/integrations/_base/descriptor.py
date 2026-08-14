"""Integration descriptor — the per-vendor source of truth for registry metadata.

Vendors register a descriptor here; the scattered integration registries
(secret-field map, MCP-server map, …) derive their per-vendor entries from it
instead of hardcoding them.

Descriptors are found by scanning ``core/integrations/*/descriptor.py``, not by
an import list. A descriptor missing from such a list never runs its
``register_descriptor`` call and goes silently dead — which is exactly how
darktrace's became dead scaffolding before #557 removed it.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

_SLICES_DIR = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class IntegrationField:
    name: str
    env_suffix: Optional[str] = None
    secret: bool = False


@dataclass(frozen=True)
class IntegrationDescriptor:
    """One code-backed integration's registry facts.

    ``fields`` is the *complete* field list, not just the secret ones: the
    config resolver keys its result off it, so a server can only read what its
    descriptor declares, and the catalog-parity ratchet compares the two
    statically instead of parsing server source.

    ``mcp_server_names`` is a tuple because one vendor can back several servers
    — Splunk has both an official server and the self-hosted one Vigil ships.
    """

    id: str
    category: str
    mcp_server_names: Tuple[str, ...] = ()
    fields: Tuple[IntegrationField, ...] = ()

    @property
    def secret_fields(self) -> Tuple[str, ...]:
        return tuple(f.name for f in self.fields if f.secret)

    @property
    def field_names(self) -> Tuple[str, ...]:
        return tuple(f.name for f in self.fields)


_REGISTRY: Dict[str, IntegrationDescriptor] = {}
_discovered = False


def register_descriptor(descriptor: IntegrationDescriptor) -> IntegrationDescriptor:
    _REGISTRY[descriptor.id] = descriptor
    return descriptor


def _discover() -> None:
    """Import every vendor slice's descriptor module exactly once.

    The flag is set before the loop so a descriptor that reaches back into this
    module can't recurse. Import errors propagate: a broken descriptor should
    fail loudly rather than leave a vendor silently unregistered.
    """
    global _discovered
    if _discovered:
        return
    _discovered = True
    for path in sorted(_SLICES_DIR.glob("*/descriptor.py")):
        package = path.parent.name
        if package.startswith("_"):
            continue
        importlib.import_module(f"core.integrations.{package}.descriptor")


def get_descriptor(integration_id: str) -> Optional[IntegrationDescriptor]:
    _discover()
    return _REGISTRY.get(integration_id)


def iter_descriptors() -> Tuple[IntegrationDescriptor, ...]:
    _discover()
    return tuple(_REGISTRY.values())
