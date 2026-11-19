from enum import StrEnum

class SuspensionReason(StrEnum):
    NON_PAYMENT = "non_payment"
    OTHER = "other"

    def __str__(self) -> str:
        return str(self.value)
