from enum import StrEnum

class PlanEffectsItemResource(StrEnum):
    ACCOUNT = "account"
    BUCKET = "bucket"
    KEY = "key"

    def __str__(self) -> str:
        return str(self.value)
