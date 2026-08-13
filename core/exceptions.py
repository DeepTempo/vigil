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
