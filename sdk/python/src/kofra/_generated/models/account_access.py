from enum import StrEnum

class AccountAccess(StrEnum):
    FULL = "full"
    NONE = "none"
    READ_ONLY = "read_only"

    def __str__(self) -> str:
        return str(self.value)
