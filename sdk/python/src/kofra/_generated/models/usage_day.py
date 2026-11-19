from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.usage_day_status import UsageDayStatus
from typing import cast
import datetime






T = TypeVar("T", bound="UsageDay")



@_attrs_define
class UsageDay:
    """ 
        Attributes:
            day (datetime.date):
            status (UsageDayStatus):
            peak_stored_bytes (int):
            uploaded_bytes (int):
            downloaded_bytes (int):
            requests_approx (int): Approximate number of S3 requests that day.
     """

    day: datetime.date
    status: UsageDayStatus
    peak_stored_bytes: int
    uploaded_bytes: int
    downloaded_bytes: int
    requests_approx: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        day = self.day.isoformat()

        status = self.status.value

        peak_stored_bytes = self.peak_stored_bytes

        uploaded_bytes = self.uploaded_bytes

        downloaded_bytes = self.downloaded_bytes

        requests_approx = self.requests_approx


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "day": day,
            "status": status,
            "peak_stored_bytes": peak_stored_bytes,
            "uploaded_bytes": uploaded_bytes,
            "downloaded_bytes": downloaded_bytes,
            "requests_approx": requests_approx,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        day = datetime.date.fromisoformat(d.pop("day"))




        status = UsageDayStatus(d.pop("status"))




        peak_stored_bytes = d.pop("peak_stored_bytes")

        uploaded_bytes = d.pop("uploaded_bytes")

        downloaded_bytes = d.pop("downloaded_bytes")

        requests_approx = d.pop("requests_approx")

        usage_day = cls(
            day=day,
            status=status,
            peak_stored_bytes=peak_stored_bytes,
            uploaded_bytes=uploaded_bytes,
            downloaded_bytes=downloaded_bytes,
            requests_approx=requests_approx,
        )


        usage_day.additional_properties = d
        return usage_day

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
