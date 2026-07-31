"""Launcher for the ARQ LLM worker.

Python 3.12+ removed implicit event loop creation in the main thread.
This wrapper ensures an event loop exists before ARQ's Worker initialises.

Usage:
    python -m core.llm.gateway.run_worker
"""

import asyncio

from arq.worker import run_worker
from core.llm.gateway.worker import WorkerSettings


def main():
    asyncio.set_event_loop(asyncio.new_event_loop())
    run_worker(WorkerSettings)


if __name__ == "__main__":
    main()
