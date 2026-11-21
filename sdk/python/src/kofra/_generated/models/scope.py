from enum import StrEnum

class Scope(StrEnum):
    ACCOUNTDELETE = "account:delete"
    ACCOUNTREAD = "account:read"
    AUDITREAD = "audit:read"
    BUCKETSDELETE = "buckets:delete"
    BUCKETSREAD = "buckets:read"
    BUCKETSWRITE = "buckets:write"
    EVENTSREAD = "events:read"
    KEYSREAD = "keys:read"
    KEYSWRITE = "keys:write"
    OBJECTSREAD = "objects:read"
    TOKENSREAD = "tokens:read"
    TOKENSWRITE = "tokens:write"
    USAGEREAD = "usage:read"

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def _missing_(cls, value: object) -> "StrEnum | None":
        # A value added to the API after this SDK was generated reads as
        # OTHER and keeps the value as sent; check it with .name == "OTHER".
        if not isinstance(value, str):
            return None
        member = str.__new__(cls, value)
        member._name_ = "OTHER"
        member._value_ = value
        return member
