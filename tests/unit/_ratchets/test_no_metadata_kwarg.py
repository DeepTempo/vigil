"""No ORM model may be constructed with ``metadata=``.

``Base.__init__`` refuses the kwarg at runtime (see #559), but only on lines that
actually execute. A construction sitting in a branch no test reaches would still
ship, and would still be invisible on inspection — ``metadata=`` reads as a
perfectly ordinary column. This scans the source instead, so the mistake cannot
survive review anywhere in the tree.

Scoped like the other ratchets: first-party packages only, derived from the model
registry rather than a hand-written list of class names, so a new model is covered
the moment it is declared.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator, Tuple

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGES = ("core", "services", "tools")

pytestmark = pytest.mark.unit


def _model_names() -> set[str]:
    """Every mapped class name, taken from the declarative registry."""
    from core.storage.models import Base

    return {mapper.class_.__name__ for mapper in Base.registry.mappers}


def _model_constructions() -> Iterator[Tuple[Path, int, str, set]]:
    """Every call whose callee shares a name with a mapped class.

    Name-matching, so a non-model class that happens to share a model's name
    would be scanned too. That only ever costs a false positive on a
    ``metadata=`` kwarg, which is worth catching either way.
    """
    names = _model_names()
    for package in PACKAGES:
        for path in sorted((REPO_ROOT / package).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = (
                    func.attr
                    if isinstance(func, ast.Attribute)
                    else getattr(func, "id", None)
                )
                if name in names:
                    yield (
                        path.relative_to(REPO_ROOT),
                        node.lineno,
                        name,
                        {kw.arg for kw in node.keywords},
                    )


def test_scanned_packages_exist():
    """``Path.rglob`` on a missing directory yields nothing and raises nothing.

    A package rename would therefore turn this whole file green while checking
    less and less of the tree.
    """
    missing = [name for name in PACKAGES if not (REPO_ROOT / name).is_dir()]
    assert not missing, f"ratchet scans packages that no longer exist: {missing}"


def test_the_scan_finds_model_constructions():
    """Guard the guard: a scan that matches nothing would pass vacuously."""
    assert list(_model_constructions())


def test_no_model_is_constructed_with_a_metadata_kwarg():
    offenders = [
        f"{path}:{lineno} {model}(metadata=...)"
        for path, lineno, model, kwargs in _model_constructions()
        if "metadata" in kwargs
    ]

    assert not offenders, (
        "metadata= on a declarative model shadows Base.metadata and never "
        "reaches a column; pass the renamed column instead (see #559): "
        f"{offenders}"
    )
