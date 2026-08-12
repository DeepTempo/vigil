# How the TypeScript agent layer proves it is the caller. Shared by every
# /internal endpoint: a security check written twice is one edit from a hole.

from __future__ import annotations

import ipaddress
from typing import Optional

from fastapi import HTTPException, Request

from core.secrets import get_secret

TOKEN_SECRET = "AGENT_INTERNAL_TOKEN"


def _loopback(request: Request) -> bool:
    host = request.client.host if request.client is not None else ""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# Both checks or neither: a shared secret on a public bind is one leak from open,
# and a loopback bind alone trusts every process on the box.
def authorise(request: Request, presented: Optional[str], what: str) -> None:
    if not _loopback(request):
        raise HTTPException(status_code=403, detail=f"{what} is loopback only")
    expected = get_secret(TOKEN_SECRET)
    if not expected or presented != f"Bearer {expected}":
        raise HTTPException(status_code=401, detail="bad or missing internal token")
