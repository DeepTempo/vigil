# Storage tests

`test_database_models.py` was deleted in this change, along with the
`tests/unit/conftest.py` that existed only to fake the package it imported.

Its 19 cases imported `deeptempo_core.database.models` and were **skipped in
every environment** — the submodule was never initialised here, so `conftest.py`
stubbed `User`, `Case`, `Finding` and `SLAPolicy` as empty sentinel classes just
so collection would succeed and the skip mark could take effect. They asserted
nothing about Vigil's own models, which live in `core/storage/models.py`.

Real coverage of those models needs DB fixtures, which `tests/conftest.py` does
not yet provide. That gap is unchanged by this deletion; what is gone is a stub
that made a missing package look present.
