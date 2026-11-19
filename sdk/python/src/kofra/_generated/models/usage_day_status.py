from enum import StrEnum

class UsageDayStatus(StrEnum):
    FINAL = "final"
    PROVISIONAL = "provisional"
    UNDER_REVIEW = "under_review"

    def __str__(self) -> str:
        return str(self.value)
