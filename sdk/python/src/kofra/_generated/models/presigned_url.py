from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.presigned_url_method import PresignedUrlMethod
from typing import cast
import datetime






T = TypeVar("T", bound="PresignedUrl")



@_attrs_define
class PresignedUrl:
    """ 
        Attributes:
            method (PresignedUrlMethod):
            url (str):
            expires_at (datetime.datetime): RFC 3339 timestamp in UTC.
     """

    method: PresignedUrlMethod
    url: str
    expires_at: datetime.datetime
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        method = self.method.value

        url = self.url

        expires_at = self.expires_at.isoformat()


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "method": method,
            "url": url,
            "expires_at": expires_at,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        method = PresignedUrlMethod(d.pop("method"))




        url = d.pop("url")

        expires_at = datetime.datetime.fromisoformat(d.pop("expires_at"))




        presigned_url = cls(
            method=method,
            url=url,
            expires_at=expires_at,
        )


        presigned_url.additional_properties = d
        return presigned_url

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
