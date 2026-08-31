import importlib.util

import pytest

from core.config import REPO_ROOT
from services.worker import WORKER_MODULE

pytestmark = pytest.mark.unit

# Every deploy path that launches the worker. The -m string is duplicated across
# them by necessity, so drift here is silent until a container fails to boot.
WIRING = (
    "infra/docker/docker-compose.yml",
    "infra/helm/vigil/templates/llm-worker-deployment.yaml",
    "infra/helm/vigil/values.yaml",
    "start.sh",
)


def test_entrypoint_module_exists():
    assert importlib.util.find_spec(f"{WORKER_MODULE}.__main__") is not None


@pytest.mark.parametrize("rel_path", WIRING)
def test_wiring_names_the_current_entrypoint(rel_path):
    text = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert WORKER_MODULE in text, f"{rel_path} does not name {WORKER_MODULE}"


def _daemon_branch(start_sh_text):
    # Isolate the text after start.sh's one top-level else (daemon) branch,
    # so a check against it can't be satisfied by the foreground branch.
    _, sep, after_else = start_sh_text.partition("\nelse\n")
    assert sep, "expected a single top-level else (daemon) branch in start.sh"
    return after_else


def test_daemon_mode_starts_worker_unconditionally():
    # Regression for #581: daemon mode must start the LLM worker itself.
    daemon_branch = _daemon_branch((REPO_ROOT / "start.sh").read_text(encoding="utf-8"))
    assert WORKER_MODULE in daemon_branch, "daemon mode does not start the LLM worker"
    assert (
        "llm_worker.pid" in daemon_branch
    ), "daemon mode does not write the worker pidfile shutdown_all.sh expects"
