from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
  from ..models.grant import Grant





T = TypeVar("T", bound="AccessKeyCreate")



@_attrs_define
class AccessKeyCreate:
    """ 
        Attributes:
            grants (list[Grant]):
            name (str | Unset):
     """

    grants: list[Grant]
    name: str | Unset = UNSET





    def to_dict(self) -> dict[str, Any]:
        from ..models.grant import Grant # noqa: PLC0415
        grants = []
        for grants_item_data in self.grants:
            grants_item = grants_item_data.to_dict()
            grants.append(grants_item)



        name = self.name


        field_dict: dict[str, Any] = {}

        field_dict.update({
            "grants": grants,
        })
        if name is not UNSET:
            field_dict["name"] = name

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.grant import Grant # noqa: PLC0415
        d = dict(src_dict)
        grants = []
        _grants = d.pop("grants")
        for grants_item_data in (_grants):
            grants_item = Grant.from_dict(grants_item_data)



            grants.append(grants_item)


        name = d.pop("name", UNSET)

        access_key_create = cls(
            grants=grants,
            name=name,
        )

        return access_key_create

