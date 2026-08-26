import asyncio

from arq.worker import run_worker

from core.config import validate_settings_or_exit


def main():
    validate_settings_or_exit()
    # jobs.py constructs Settings at import; must stay below the guard.
    from services.worker.jobs import WorkerSettings

    # Python 3.12+ dropped implicit loop creation; ARQ's Worker needs one to exist.
    asyncio.set_event_loop(asyncio.new_event_loop())
    run_worker(WorkerSettings)


if __name__ == "__main__":
    main()
