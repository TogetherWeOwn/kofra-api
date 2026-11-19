from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
  from ..models.grant_input import GrantInput





T = TypeVar("T", bound="AccessKeyCreate")



@_attrs_define
class AccessKeyCreate:
    """ 
        Attributes:
            grants (list[GrantInput]): 1 to 32 grants, each bucket at most once; a bucket listed twice is refused with
                `validation_failed`.
            name (str | Unset): A label for people; not used for access.
     """

    grants: list[GrantInput]
    name: str | Unset = UNSET





    def to_dict(self) -> dict[str, Any]:
        from ..models.grant_input import GrantInput # noqa: PLC0415
        grants = []
        for componentsschemas_grants_item_data in self.grants:
            componentsschemas_grants_item = componentsschemas_grants_item_data.to_dict()
            grants.append(componentsschemas_grants_item)



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
        from ..models.grant_input import GrantInput # noqa: PLC0415
        d = dict(src_dict)
        grants = []
        _grants = d.pop("grants")
        for componentsschemas_grants_item_data in (_grants):
            componentsschemas_grants_item = GrantInput.from_dict(componentsschemas_grants_item_data)



            grants.append(componentsschemas_grants_item)


        name = d.pop("name", UNSET)

        access_key_create = cls(
            grants=grants,
            name=name,
        )

        return access_key_create

