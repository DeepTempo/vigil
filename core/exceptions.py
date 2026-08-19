class SOCError(Exception):
    def __init__(self, message: str, code: str = "SOC_ERROR"):
        self.message = message
        self.code = code
        super().__init__(message)


class DatabaseError(SOCError):
    def __init__(self, message: str):
        super().__init__(message, "DATABASE_ERROR")
