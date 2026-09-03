"""Runtime-fetched MCP servers must pin an exact artifact, not registry HEAD.

npx / uvx / docker entries in mcp-config.json download code at process start.
An unpinned spec, a version range, @latest, or a git default branch makes two
identical deploys diverge and is a supply-chain footgun. In-repo python3
servers and joe-sandbox's local ``uv --directory`` clone are not registry
resolves and are left alone.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_MCP_CONFIG = _REPO_ROOT / "mcp-config.json"

_FLOATING_GIT_REFS = {"HEAD", "head", "main", "master", "latest", "dev", "develop"}
_RANGE_IN_VERSION = re.compile(r"[<>=^~*]")
_EXACT_PYPI = re.compile(r"==[A-Za-z0-9][A-Za-z0-9._-]*$")
_GIT_REF = re.compile(r"\.git@([^#]+)$")
_SHA256 = re.compile(r"@sha256:[0-9a-f]{64}$")

# uvx flags that consume the next argv token as a package spec.
_UVX_SPEC_FLAGS = {
    "--from",
    "--with",
    "--with-editable",
    "--with-requirements",
}


def _servers() -> dict[str, dict]:
    raw = json.loads(_MCP_CONFIG.read_text())["mcpServers"]
    return {k: v for k, v in raw.items() if isinstance(v, dict)}


def _npm_version(spec: str) -> str | None:
    """Return the version suffix of an npm package spec, or None if missing."""
    rest = spec[1:] if spec.startswith("@") else spec
    if "@" not in rest:
        return None
    return rest.rsplit("@", 1)[1]


def _npm_pinned(spec: str) -> bool:
    version = _npm_version(spec)
    return bool(version) and not _RANGE_IN_VERSION.search(version) and version != "latest"


def _npx_package(args: list[str]) -> str | None:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-p", "--package") and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith("-"):
            i += 1
            continue
        return arg
    return None


def _pypi_or_git_pinned(spec: str) -> bool:
    if spec.startswith("git+") or "git+" in spec:
        match = _GIT_REF.search(spec.split("#", 1)[0])
        return bool(match) and match.group(1) not in _FLOATING_GIT_REFS
    return bool(_EXACT_PYPI.search(spec))


def _uvx_unpinned(args: list[str]) -> list[str]:
    """Return package specs that are missing an exact pin."""
    unpinned: list[str] = []
    has_from = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _UVX_SPEC_FLAGS and i + 1 < len(args):
            spec = args[i + 1]
            if arg == "--from":
                has_from = True
            if not _pypi_or_git_pinned(spec):
                unpinned.append(spec)
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        # First positional is the package unless --from already named it.
        if not has_from and not _pypi_or_git_pinned(arg):
            unpinned.append(arg)
        break
    return unpinned


def _docker_image(args: list[str]) -> str | None:
    skip_next = False
    images: list[str] = []
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in ("-e", "--env", "-v", "--volume", "-w", "--workdir", "--name", "-u"):
            skip_next = True
            continue
        if arg.startswith("-") or arg == "run":
            continue
        images.append(arg)
    return images[-1] if images else None


@pytest.mark.unit
def test_runtime_fetched_mcp_servers_are_pinned():
    unpinned: dict[str, str] = {}
    inspected = 0
    for name, config in _servers().items():
        command = config.get("command")
        args = [a for a in config.get("args") or [] if isinstance(a, str)]
        if command == "npx":
            inspected += 1
            package = _npx_package(args)
            if not package or not _npm_pinned(package):
                unpinned[name] = package or "(missing npx package)"
        elif command == "uvx":
            inspected += 1
            leftover = _uvx_unpinned(args)
            if leftover:
                unpinned[name] = ", ".join(leftover)
        elif command == "docker":
            inspected += 1
            image = _docker_image(args)
            if not image or not _SHA256.search(image):
                unpinned[name] = image or "(missing docker image)"

    assert inspected >= 15, (
        "expected to inspect npx/uvx/docker MCP servers; the ratchet is "
        f"vacuous if launchers were renamed ({inspected} found)"
    )
    assert not unpinned, (
        "runtime-fetched MCP servers must pin an exact version, git tag/SHA, "
        "or image digest — not @latest, a range, or git HEAD:\n"
        + "\n".join(f"  {name}: {detail}" for name, detail in sorted(unpinned.items()))
    )


@pytest.mark.unit
def test_mcp_remote_stays_inside_the_0_1_cve_window():
    """CVE-2025-6514 is fixed in 0.1.16; jumping to 0.8.x is a separate decision."""
    offenders: dict[str, str] = {}
    found = 0
    for name, config in _servers().items():
        for arg in config.get("args") or []:
            if not isinstance(arg, str) or not arg.startswith("mcp-remote"):
                continue
            found += 1
            version = _npm_version(arg) or ""
            if not version.startswith("0.1.") or _RANGE_IN_VERSION.search(version):
                offenders[name] = arg
    assert found, "no mcp-remote specs found; the CVE pin ratchet is vacuous"
    assert not offenders, (
        "mcp-remote must stay on an exact 0.1.x pin (CVE-2025-6514 window), "
        f"not a range or 0.8.x: {offenders}"
    )
