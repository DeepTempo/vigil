import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_startup(command: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["DAEMON_HEALTH_PORT"] = "not-an-int"
    env["DEV_MODE"] = "true"
    env["PYTHONPATH"] = (
        f"{REPO_ROOT}{os.pathsep}{env['PYTHONPATH']}"
        if env.get("PYTHONPATH")
        else str(REPO_ROOT)
    )
    return subprocess.run(
        [sys.executable, "-c", command],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_api_startup_reports_labeled_configuration_error():
    result = _run_startup("import services.api.main")

    assert result.returncode == os.EX_CONFIG
    assert result.stderr.count("configuration error:") == 1
    assert "daemon_health_port" in result.stderr
    assert "Traceback" not in result.stderr
    assert "ValidationError" not in result.stderr


def test_daemon_entrypoint_reports_labeled_configuration_error():
    result = _run_startup("from services.daemon.main import main; main()")

    assert result.returncode == os.EX_CONFIG
    assert result.stderr.count("configuration error:") == 1
    assert "daemon_health_port" in result.stderr
    assert "Traceback" not in result.stderr
    assert "ValidationError" not in result.stderr
