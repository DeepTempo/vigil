# Supervises the ARQ worker as a child process of the daemon. The worker drains
# the arq:llm queue for ALL LLM traffic (chat, AI insights, agent runner, daemon
# triage), not just autonomous orchestration, so it runs unconditionally while
# the daemon runs — matching foreground, docker-compose and the Helm chart.

import asyncio
import logging
import os
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

PROJECT_ROOT = str(Path(__file__).resolve().parents[2])

# The -m entrypoint, shared with compose, the Helm Deployment and start.sh.
WORKER_MODULE = "services.worker"


class LLMWorkerManager:
    def __init__(self):
        self._process: subprocess.Popen | None = None

    async def run(self, shutdown_event: asyncio.Event):
        logger.info("LLM Worker Manager started")

        if not self._is_running():
            self._start_worker()

        while not shutdown_event.is_set():
            if not self._is_running():
                logger.warning("LLM Worker exited unexpectedly — restarting")
                self._start_worker()

            try:  # sleep, but wake immediately on shutdown
                await asyncio.wait_for(shutdown_event.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass

        self._stop_worker()
        logger.info("LLM Worker Manager shutdown complete")

    def _start_worker(self):
        # Exports the parent env into a child process; not a config read.
        env = {**os.environ, "PYTHONPATH": PROJECT_ROOT}  # noqa: ENV001
        log_path = Path(PROJECT_ROOT) / "logs" / "llm_worker.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            log_file = open(log_path, "a")
            self._process = subprocess.Popen(
                [sys.executable, "-m", WORKER_MODULE],
                cwd=PROJECT_ROOT,
                env=env,
                stdout=log_file,
                stderr=log_file,
            )
            logger.info(
                "LLM Worker started (PID: %d) — logs: %s",
                self._process.pid,
                log_path,
            )
        except Exception as exc:
            logger.error("Failed to start LLM Worker: %s", exc)
            self._process = None

    def _stop_worker(self):
        if not self._is_running():
            self._process = None
            return

        pid = self._process.pid
        self._process.terminate()
        try:
            self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            logger.warning("LLM Worker (PID %d) did not exit, killing", pid)
            self._process.kill()
            self._process.wait(timeout=5)

        logger.info("LLM Worker stopped (PID: %d)", pid)
        self._process = None

    def _is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None
