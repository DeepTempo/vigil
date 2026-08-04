"""Shared FastAPI dependencies.

The per-request transaction boundary lives here rather than in
``database.connection`` because it is a web concern — ``services.unit_of_work``
stays framework-free so services and the daemon can use it too.
"""

from typing import Annotated, Generator

from fastapi import Depends
from sqlalchemy.orm import Session

from services.unit_of_work import unit_of_work


def request_unit_of_work() -> Generator[Session, None, None]:
    """Yield a session whose transaction spans the whole request.

    Commits once if the endpoint returns normally, rolls back if it raises
    (``HTTPException`` included), and always closes. Endpoints and the services
    they call must not commit or roll back themselves.
    """
    with unit_of_work() as session:
        yield session


# Depend on this alias rather than writing out ``Depends(request_unit_of_work)``.
# The ``scope="function"`` is load-bearing: with the default request scope,
# teardown runs *after* the response has been sent, so a failed commit returns
# the success body with a 200 while the write is rolled back. Function scope
# closes the boundary before the response is emitted, turning that into a 500.
UnitOfWorkSession = Annotated[Session, Depends(request_unit_of_work, scope="function")]
