import importlib.util

import pytest

from core.config import REPO_ROOT
from services.worker.manager import WORKER_MODULE

pytestmark = pytest.mark.unit

# Every deploy path that launches the worker. The -m string is duplicated across
# them by necessity, so drift here is silent until a container fails to boot.
WIRING = (
    "docker/docker-compose.yml",
    "helm/vigil/templates/llm-worker-deployment.yaml",
    "helm/vigil/values.yaml",
    "helm/vigil/README.md",
    "start.sh",
)

STALE = ("services.run_llm_worker", "core.llm.gateway.run_worker")


def test_entrypoint_module_is_importable():
    assert importlib.util.find_spec(f"{WORKER_MODULE}.__main__") is not None


@pytest.mark.parametrize("rel_path", WIRING)
def test_wiring_names_the_current_entrypoint(rel_path):
    text = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert WORKER_MODULE in text, f"{rel_path} does not name {WORKER_MODULE}"
    for stale in STALE:
        assert stale not in text, f"{rel_path} still names {stale}"
