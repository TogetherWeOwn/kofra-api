from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset







T = TypeVar("T", bound="FieldError")



@_attrs_define
class FieldError:
    """ 
        Attributes:
            pointer (str): JSON pointer to the field (RFC 6901), or `#query/<name>`, `#path/<name>` or `#header/<name>` for
                parameters.
            code (str):
            detail (str):
     """

    pointer: str
    code: str
    detail: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        pointer = self.pointer

        code = self.code

        detail = self.detail


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "pointer": pointer,
            "code": code,
            "detail": detail,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        pointer = d.pop("pointer")

        code = d.pop("code")

        detail = d.pop("detail")

        field_error = cls(
            pointer=pointer,
            code=code,
            detail=detail,
        )


        field_error.additional_properties = d
        return field_error

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
