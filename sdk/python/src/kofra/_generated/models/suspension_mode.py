from enum import StrEnum

class SuspensionMode(StrEnum):
    BLOCKED = "blocked"
    READ_ONLY = "read_only"

    def __str__(self) -> str:
        return str(self.value)
