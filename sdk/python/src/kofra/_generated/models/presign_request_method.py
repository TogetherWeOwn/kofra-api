from enum import StrEnum

class PresignRequestMethod(StrEnum):
    GET = "GET"

    def __str__(self) -> str:
        return str(self.value)
