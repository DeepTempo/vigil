"""Pydantic ORM-mode schemas for the models in ``database.models``.

Each model's serialized shape is declared here once, replacing the
hand-written ``to_dict()`` methods that previously defined it implicitly.
"""

from database.schemas.base import ORMSchema

__all__ = ["ORMSchema"]
