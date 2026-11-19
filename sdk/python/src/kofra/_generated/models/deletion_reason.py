from enum import StrEnum

class DeletionReason(StrEnum):
    CUSTOMER = "customer"
    NON_PAYMENT = "non_payment"

    def __str__(self) -> str:
        return str(self.value)
