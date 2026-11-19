from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.presign_request_method import PresignRequestMethod
from ..types import UNSET, Unset






T = TypeVar("T", bound="PresignRequest")



@_attrs_define
class PresignRequest:
    """ 
        Attributes:
            bucket (str): 3 to 63 lowercase letters, digits or hyphens; starts and ends with a letter or digit.
            key (str): The object key.
            method (PresignRequestMethod): Only downloads are offered for now.
            expires_in_seconds (int | Unset):  Default: 900.
     """

    bucket: str
    key: str
    method: PresignRequestMethod
    expires_in_seconds: int | Unset = 900





    def to_dict(self) -> dict[str, Any]:
        bucket = self.bucket

        key = self.key

        method = self.method.value

        expires_in_seconds = self.expires_in_seconds


        field_dict: dict[str, Any] = {}

        field_dict.update({
            "bucket": bucket,
            "key": key,
            "method": method,
        })
        if expires_in_seconds is not UNSET:
            field_dict["expires_in_seconds"] = expires_in_seconds

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        bucket = d.pop("bucket")

        key = d.pop("key")

        method = PresignRequestMethod(d.pop("method"))




        expires_in_seconds = d.pop("expires_in_seconds", UNSET)

        presign_request = cls(
            bucket=bucket,
            key=key,
            method=method,
            expires_in_seconds=expires_in_seconds,
        )

        return presign_request

