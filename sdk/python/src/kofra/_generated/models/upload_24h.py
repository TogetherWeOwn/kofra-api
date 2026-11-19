from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from typing import cast
import datetime






T = TypeVar("T", bound="Upload24H")



@_attrs_define
class Upload24H:
    """ Uploads in the current 24-hour window.

        Attributes:
            limit_bytes (int | None):
            used_bytes (int):
            remaining_bytes (int | None):
            resets_at (datetime.datetime): RFC 3339 timestamp in UTC.
     """

    limit_bytes: int | None
    used_bytes: int
    remaining_bytes: int | None
    resets_at: datetime.datetime
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        limit_bytes: int | None
        limit_bytes = self.limit_bytes

        used_bytes = self.used_bytes

        remaining_bytes: int | None
        remaining_bytes = self.remaining_bytes

        resets_at = self.resets_at.isoformat()


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "limit_bytes": limit_bytes,
            "used_bytes": used_bytes,
            "remaining_bytes": remaining_bytes,
            "resets_at": resets_at,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        def _parse_limit_bytes(data: object) -> int | None:
            if data is None:
                return data
            return cast(int | None, data)

        limit_bytes = _parse_limit_bytes(d.pop("limit_bytes"))


        used_bytes = d.pop("used_bytes")

        def _parse_remaining_bytes(data: object) -> int | None:
            if data is None:
                return data
            return cast(int | None, data)

        remaining_bytes = _parse_remaining_bytes(d.pop("remaining_bytes"))


        resets_at = datetime.datetime.fromisoformat(d.pop("resets_at"))




        upload_24h = cls(
            limit_bytes=limit_bytes,
            used_bytes=used_bytes,
            remaining_bytes=remaining_bytes,
            resets_at=resets_at,
        )


        upload_24h.additional_properties = d
        return upload_24h

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
