from enum import StrEnum

class UsageDayStatus(StrEnum):
    FINAL = "final"
    PROVISIONAL = "provisional"
    UNDER_REVIEW = "under_review"

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def _missing_(cls, value: object) -> "StrEnum | None":
        # A value added to the API after this SDK was generated reads as
        # OTHER and keeps the value as sent.
        if not isinstance(value, str):
            return None
        member = str.__new__(cls, value)
        member._name_ = "OTHER"
        member._value_ = value
        return member
