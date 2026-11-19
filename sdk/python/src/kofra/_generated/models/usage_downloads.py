from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from typing import cast
import datetime






T = TypeVar("T", bound="UsageDownloads")



@_attrs_define
class UsageDownloads:
    """ 
        Attributes:
            period_start (datetime.datetime): RFC 3339 timestamp in UTC.
            allowance_bytes (int | None):
            used_bytes (int):
            over_bytes (int):
     """

    period_start: datetime.datetime
    allowance_bytes: int | None
    used_bytes: int
    over_bytes: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        period_start = self.period_start.isoformat()

        allowance_bytes: int | None
        allowance_bytes = self.allowance_bytes

        used_bytes = self.used_bytes

        over_bytes = self.over_bytes


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "period_start": period_start,
            "allowance_bytes": allowance_bytes,
            "used_bytes": used_bytes,
            "over_bytes": over_bytes,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        period_start = datetime.datetime.fromisoformat(d.pop("period_start"))




        def _parse_allowance_bytes(data: object) -> int | None:
            if data is None:
                return data
            return cast(int | None, data)

        allowance_bytes = _parse_allowance_bytes(d.pop("allowance_bytes"))


        used_bytes = d.pop("used_bytes")

        over_bytes = d.pop("over_bytes")

        usage_downloads = cls(
            period_start=period_start,
            allowance_bytes=allowance_bytes,
            used_bytes=used_bytes,
            over_bytes=over_bytes,
        )


        usage_downloads.additional_properties = d
        return usage_downloads

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
