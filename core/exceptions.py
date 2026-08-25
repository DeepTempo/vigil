import functools
import inspect
import logging


class SOCError(Exception):
    """Base for expected domain failures.

    The API renders these directly: ``message`` reaches the client, so keep it
    free of internal detail. Subclasses set ``status_code`` to choose the HTTP
    status; anything else surfaces as a 500.
    """

    status_code: int = 500

    def __init__(self, message: str, code: str = "SOC_ERROR"):
        self.message = message
        self.code = code
        super().__init__(message)


class DatabaseError(SOCError):
    def __init__(self, message: str):
        super().__init__(message, "DATABASE_ERROR")


def default_on_error(default, *, level: str = "exception"):
    """Log and return ``default`` if the wrapped function raises.

    For service methods whose callers read a falsy result as "unavailable".
    Pass a factory (``list``, ``dict``) for mutable defaults so callers cannot
    mutate a shared instance. Do not use where the caller needs to tell failure
    apart from a legitimately empty result — raise a `SOCError` there instead.

    ``level`` names the logger method used for the failure. It defaults to
    ``"exception"`` (ERROR plus a traceback), which is right for a failure
    nobody expects. Lower it where the failure is routine and the caller has a
    real fallback — a missing table before the seed runs, pgvector absent — so
    an expected miss does not read as an incident in the log.

    Sync functions only: the wrapper cannot await, so decorating a coroutine
    would catch nothing. That raises at decoration time rather than silently.
    """

    def decorate(fn):
        if isinstance(fn, (staticmethod, classmethod)):
            # Wrapping the descriptor yields a plain function, which then binds
            # ``self`` again — every instance-style call arrives one argument
            # over and fails, and this very decorator swallows the TypeError
            # into ``default``. Put @staticmethod on the outside instead.
            raise TypeError(
                f"default_on_error must be applied under @{type(fn).__name__}, "
                "not over it"
            )
        if inspect.iscoroutinefunction(fn):
            raise TypeError(f"{fn.__qualname__}: default_on_error is sync-only")

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception:
                log = getattr(logging.getLogger(fn.__module__), level)
                log("%s failed", fn.__qualname__)
                return default() if callable(default) else default

        return wrapper

    return decorate
