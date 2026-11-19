from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.plan_effects_item_change import PlanEffectsItemChange
from ..models.plan_effects_item_resource import PlanEffectsItemResource






T = TypeVar("T", bound="PlanEffectsItem")



@_attrs_define
class PlanEffectsItem:
    """ 
        Attributes:
            resource (PlanEffectsItemResource):
            id (str):
            change (PlanEffectsItemChange):
     """

    resource: PlanEffectsItemResource
    id: str
    change: PlanEffectsItemChange
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        resource = self.resource.value

        id = self.id

        change = self.change.value


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "resource": resource,
            "id": id,
            "change": change,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        resource = PlanEffectsItemResource(d.pop("resource"))




        id = d.pop("id")

        change = PlanEffectsItemChange(d.pop("change"))




        plan_effects_item = cls(
            resource=resource,
            id=id,
            change=change,
        )


        plan_effects_item.additional_properties = d
        return plan_effects_item

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
