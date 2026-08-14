import ast
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parents[3] / "tools"


def _verify_false_lines(path: Path):
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg == "verify" and getattr(kw.value, "value", None) is False:
                yield kw.value.lineno


@pytest.mark.unit
def test_no_hardcoded_tls_verify_disabled_in_tools():
    violations = [
        f"{path.relative_to(TOOLS_DIR.parent)}:{lineno}"
        for path in TOOLS_DIR.rglob("*.py")
        for lineno in _verify_false_lines(path)
    ]
    assert not violations, (
        "Hardcoded 'verify=False' disables TLS verification unconditionally. "
        "Use verify=config.get('verify_ssl', True) so operators opt out "
        "explicitly.\n" + "\n".join(violations)
    )
