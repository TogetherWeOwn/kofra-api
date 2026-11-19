from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.grant_access import GrantAccess






T = TypeVar("T", bound="Grant")



@_attrs_define
class Grant:
    """ 
        Attributes:
            bucket (str): 3 to 63 lowercase letters, digits or hyphens; starts and ends with a letter or digit.
            access (GrantAccess): `read`: list and read objects. `read_write`: also write and delete objects.
     """

    bucket: str
    access: GrantAccess





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

        access = GrantAccess(d.pop("access"))




        grant = cls(
            bucket=bucket,
            access=access,
        )

        return grant

