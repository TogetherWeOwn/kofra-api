from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.grant_input_access import GrantInputAccess






T = TypeVar("T", bound="GrantInput")



@_attrs_define
class GrantInput:
    """ A grant in a request. Each bucket at most once per request; a bucket listed twice is refused with
    `validation_failed`.

        Attributes:
            bucket (str): 3 to 63 lowercase letters, digits or hyphens; starts and ends with a letter or digit.
            access (GrantInputAccess): `read`: list and read objects. `read_write`: also write and delete objects.
     """

    bucket: str
    access: GrantInputAccess





    def to_dict(self) -> dict[str, Any]:
        bucket = self.bucket

        access = self.access.value


        field_dict: dict[str, Any] = {}

        field_dict.update({
            "bucket": bucket,
            "access": access,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        bucket = d.pop("bucket")

        access = GrantInputAccess(d.pop("access"))




        grant_input = cls(
            bucket=bucket,
            access=access,
        )

        return grant_input

