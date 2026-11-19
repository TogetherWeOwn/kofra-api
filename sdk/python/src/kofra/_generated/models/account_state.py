from enum import StrEnum

class AccountState(StrEnum):
    ACTIVE = "active"
    DELETING = "deleting"
    SUSPENDED = "suspended"

    def __str__(self) -> str:
        return str(self.value)
