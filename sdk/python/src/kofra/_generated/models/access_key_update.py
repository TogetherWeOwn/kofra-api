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





T = TypeVar("T", bound="AccessKeyUpdate")



@_attrs_define
class AccessKeyUpdate:
    """ 
        Attributes:
            name (str | Unset):
            grants (list[Grant] | Unset): Grants to add or widen. Grants not listed are kept.
     """

    name: str | Unset = UNSET
    grants: list[Grant] | Unset = UNSET





    def to_dict(self) -> dict[str, Any]:
        from ..models.grant import Grant # noqa: PLC0415
        name = self.name

        grants: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.grants, Unset):
            grants = []
            for grants_item_data in self.grants:
                grants_item = grants_item_data.to_dict()
                grants.append(grants_item)




        field_dict: dict[str, Any] = {}

        field_dict.update({
        })
        if name is not UNSET:
            field_dict["name"] = name
        if grants is not UNSET:
            field_dict["grants"] = grants

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.grant import Grant # noqa: PLC0415
        d = dict(src_dict)
        name = d.pop("name", UNSET)

        _grants = d.pop("grants", UNSET)
        grants: list[Grant] | Unset = UNSET
        if _grants is not UNSET:
            grants = []
            for grants_item_data in _grants:
                grants_item = Grant.from_dict(grants_item_data)



                grants.append(grants_item)


        access_key_update = cls(
            name=name,
            grants=grants,
        )

        return access_key_update

