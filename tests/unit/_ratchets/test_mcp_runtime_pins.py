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

# Concrete versions only: 1.2.3, 2025.4.8. Dist-tags, x-ranges, and pre-releases
# are not pins.
_EXACT_VERSION = re.compile(r"^[0-9]+(\.[0-9]+)*$")
_EXACT_PYPI = re.compile(r"==([0-9]+(?:\.[0-9]+)*)$")
_GIT_REF = re.compile(r"\.git@([^#]+)$")
_SHA256 = re.compile(r"@sha256:[0-9a-f]{64}$")
_MCP_REMOTE_PATCH = re.compile(r"^0\.1\.(\d+)$")
_FLOATING_GIT_REFS = {"HEAD", "head", "main", "master", "latest", "dev", "develop"}

# uvx flags whose next token is a package spec that must be pinned.
_UVX_SPEC_FLAGS = {"--from", "--with"}
# uvx flags whose next token is not a package (interpreter, path, index).
_UVX_VALUE_FLAGS = {
    "--python",
    "--with-editable",
    "--with-requirements",
    "--index",
    "--extra-index-url",
}
_DOCKER_VALUE_FLAGS = {
    "-e",
    "--env",
    "-v",
    "--volume",
    "-w",
    "--workdir",
    "--name",
    "-u",
    "--user",
    "--platform",
    "-p",
    "--publish",
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
    return bool(version) and bool(_EXACT_VERSION.fullmatch(version))


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


def _git_pinned(spec: str) -> bool:
    match = _GIT_REF.search(spec.split("#", 1)[0])
    if not match:
        return False
    ref = match.group(1)
    if ref in _FLOATING_GIT_REFS or ref.startswith(("refs/heads/", "refs/remotes/")):
        return False
    return True


def _pypi_or_git_pinned(spec: str) -> bool:
    if spec.startswith("git+") or "git+" in spec:
        return _git_pinned(spec)
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
        if arg in _UVX_VALUE_FLAGS:
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
        if arg in _DOCKER_VALUE_FLAGS:
            skip_next = True
            continue
        if arg.startswith("-") or arg == "run":
            continue
        images.append(arg)
    return images[-1] if images else None


def _mcp_remote_in_cve_window(version: str) -> bool:
    """CVE-2025-6514 is fixed in 0.1.16; stay on exact 0.1.N with N >= 16."""
    match = _MCP_REMOTE_PATCH.fullmatch(version)
    return bool(match) and int(match.group(1)) >= 16


@pytest.mark.unit
@pytest.mark.parametrize(
    "spec, ok",
    [
        ("pkg@1.2.3", True),
        ("@scope/pkg@2025.4.8", True),
        ("pkg", False),
        ("pkg@latest", False),
        ("pkg@Latest", False),
        ("pkg@next", False),
        ("pkg@^0.1.16", False),
        ("pkg@0.1.x", False),
    ],
)
def test_npm_pin_helper(spec: str, ok: bool):
    assert _npm_pinned(spec) is ok


@pytest.mark.unit
@pytest.mark.parametrize(
    "spec, ok",
    [
        ("falcon-mcp==0.19.0", True),
        ("falcon-mcp==latest", False),
        ("mcp<2", False),
        ("mcp==1.29.1", True),
        ("git+https://github.com/org/repo.git@v0.7.0", True),
        ("git+https://github.com/org/repo.git", False),
        ("git+https://github.com/org/repo.git@HEAD", False),
        ("git+https://github.com/org/repo.git@main", False),
        ("git+https://github.com/org/repo.git@refs/heads/main", False),
    ],
)
def test_pypi_or_git_pin_helper(spec: str, ok: bool):
    assert _pypi_or_git_pinned(spec) is ok


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
            if not _mcp_remote_in_cve_window(version):
                offenders[name] = arg
    assert found >= 3, (
        "expected several mcp-remote specs; the CVE pin ratchet is vacuous "
        f"if they were renamed ({found} found)"
    )
    assert not offenders, (
        "mcp-remote must stay on an exact 0.1.N pin with N>=16 "
        f"(CVE-2025-6514 window), not a range or 0.8.x: {offenders}"
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "version, ok",
    [
        ("0.1.16", True),
        ("0.1.49", True),
        ("0.1.15", False),
        ("0.1.0", False),
        ("0.1.x", False),
        ("0.8.3", False),
        ("^0.1.16", False),
    ],
)
def test_mcp_remote_cve_window_helper(version: str, ok: bool):
    assert _mcp_remote_in_cve_window(version) is ok
