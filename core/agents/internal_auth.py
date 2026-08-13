# How the TypeScript agent layer proves it is the caller. Shared by every
# /internal endpoint: a security check written twice is one edit from a hole.

from __future__ import annotations

import logging
from typing import Optional

from fastapi import HTTPException, Request

from core.secrets import get_secret

logger = logging.getLogger(__name__)

TOKEN_SECRET = "AGENT_INTERNAL_TOKEN"


# The token alone, since ADR 0014. This paired with a loopback check until #635
# made the agent layer its own Deployments, at which point every legitimate caller
# arrives from a pod address and the check refused all of them. What replaces it is
# the chart's NetworkPolicy, which names the pods that may connect rather than
# asserting "same box" -- a stronger statement, and one Kubernetes enforces.
#
# Which makes the refusal below load-bearing rather than defensive: it is now the
# only thing between a reachable pod and an open endpoint.
def authorise(request: Request, presented: Optional[str], what: str) -> None:
    expected = get_secret(TOKEN_SECRET)
    # Told apart deliberately: a deployment that never set the secret reads exactly
    # like a caller with the wrong one, and the fix for each is nothing alike.
    if not expected:
        logger.error("%s refused: %s is not configured", what, TOKEN_SECRET)
        raise HTTPException(status_code=503, detail=f"{TOKEN_SECRET} is not configured")
    if presented != f"Bearer {expected}":
        raise HTTPException(status_code=401, detail="bad or missing internal token")
