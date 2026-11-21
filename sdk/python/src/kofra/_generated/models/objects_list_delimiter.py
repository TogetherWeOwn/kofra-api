from enum import StrEnum

class ObjectsListDelimiter(StrEnum):
    SLASH = "/"

    def __str__(self) -> str:
        return str(self.value)
