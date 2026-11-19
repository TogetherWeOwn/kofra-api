from enum import StrEnum

class DeletionStatus(StrEnum):
    PENDING_CONFIRMATION = "pending_confirmation"
    SCHEDULED = "scheduled"

    def __str__(self) -> str:
        return str(self.value)
