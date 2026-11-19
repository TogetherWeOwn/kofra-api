from enum import StrEnum

class PlanEffectChange(StrEnum):
    DELETE = "delete"
    REVOKE = "revoke"
    SCHEDULE_DELETION = "schedule_deletion"

    def __str__(self) -> str:
        return str(self.value)
