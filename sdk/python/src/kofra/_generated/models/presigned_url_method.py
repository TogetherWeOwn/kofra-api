from enum import StrEnum

class PresignedUrlMethod(StrEnum):
    GET = "GET"

    def __str__(self) -> str:
        return str(self.value)
