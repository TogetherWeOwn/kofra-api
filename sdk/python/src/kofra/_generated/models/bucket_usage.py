from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from typing import cast
import datetime






T = TypeVar("T", bound="BucketUsage")



@_attrs_define
class BucketUsage:
    """ 
        Attributes:
            bucket (str): 3 to 63 lowercase letters, digits or hyphens; starts and ends with a letter or digit.
            stored_bytes (int):
            object_count (int):
            as_of (datetime.datetime): RFC 3339 timestamp in UTC.
     """

    bucket: str
    stored_bytes: int
    object_count: int
    as_of: datetime.datetime
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        bucket = self.bucket

        stored_bytes = self.stored_bytes

        object_count = self.object_count

        as_of = self.as_of.isoformat()


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "bucket": bucket,
            "stored_bytes": stored_bytes,
            "object_count": object_count,
            "as_of": as_of,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        bucket = d.pop("bucket")

        stored_bytes = d.pop("stored_bytes")

        object_count = d.pop("object_count")

        as_of = datetime.datetime.fromisoformat(d.pop("as_of"))




        bucket_usage = cls(
            bucket=bucket,
            stored_bytes=stored_bytes,
            object_count=object_count,
            as_of=as_of,
        )


        bucket_usage.additional_properties = d
        return bucket_usage

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
