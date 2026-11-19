from enum import StrEnum

class DeletionReason(StrEnum):
    CUSTOMER = "customer"
    NON_PAYMENT = "non_payment"

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def _missing_(cls, value: object) -> "StrEnum | None":
        # A value added to the API after this SDK was generated.
        if not isinstance(value, str):
            return None
        member = str.__new__(cls, value)
        member._name_ = "OTHER"
        member._value_ = value
        return member
