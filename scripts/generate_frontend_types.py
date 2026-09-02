#!/usr/bin/env python3
"""Dump the FastAPI OpenAPI spec and generate frontend TypeScript types.

Does not start a server: uses ``app.openapi()``, the same path as
``tests/security/test_route_auth_coverage.py``. Output is committed under
``clients/web/src/services/generated/`` — do not edit it by hand.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "clients" / "web"
OUT_DIR = WEB / "src" / "services" / "generated"
OUT_FILE = OUT_DIR / "schema.d.ts"
OPENAPI_TS = WEB / "node_modules" / ".bin" / "openapi-typescript"

# Match tests/conftest.py so importing the app doesn't demand JWT_SECRET_KEY
# or read a developer's .env.
os.environ.setdefault("DEV_MODE", "true")
os.environ["VIGIL_DISABLE_DOTENV"] = "1"


def _stable_operation_ids(spec: dict) -> None:
    """Rewrite operationIds from path+method.

    FastAPI derives the id from the Python function. A catch-all that handles
    several verbs therefore collides, and *which* verb FastAPI stamps on the
    shared id is not stable across ``app.openapi()`` calls — CI regen would
    flake. Path+method is unique and deterministic.
    """
    for path, methods in (spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        slug = path.strip("/").replace("/", "_").replace("{", "").replace("}", "")
        for method, op in methods.items():
            if not isinstance(op, dict) or "operationId" not in op:
                continue
            op["operationId"] = f"{method}_{slug}"


def _dump_spec(path: Path) -> None:
    from services.api.main import app

    spec = app.openapi()
    _stable_operation_ids(spec)
    path.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n")


def main() -> int:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    if not OPENAPI_TS.is_file():
        print(
            f"missing {OPENAPI_TS}; run `npm ci` in clients/web first",
            file=sys.stderr,
        )
        return 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        spec_path = Path(tmp.name)

    try:
        _dump_spec(spec_path)
        subprocess.run(
            [str(OPENAPI_TS), str(spec_path), "-o", str(OUT_FILE)],
            check=True,
        )
    finally:
        spec_path.unlink(missing_ok=True)

    print(f"wrote {OUT_FILE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
