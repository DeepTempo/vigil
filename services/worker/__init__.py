# The ARQ llm-worker process: a composition root over core.llm, run as
# `python -m services.worker`. Every deploy path (start.sh, docker-compose,
# the Helm chart) launches its own instance directly; nothing supervises it.

# The -m entrypoint, shared with compose, the Helm Deployment and start.sh.
WORKER_MODULE = "services.worker"
