from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset







T = TypeVar("T", bound="PlanTotals")



@_attrs_define
class PlanTotals:
    """ 
        Attributes:
            buckets (int):
            objects (int):
            stored_bytes (int):
            keys (int):
     """

    buckets: int
    objects: int
    stored_bytes: int
    keys: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        buckets = self.buckets

        objects = self.objects

        stored_bytes = self.stored_bytes

        keys = self.keys


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "buckets": buckets,
            "objects": objects,
            "stored_bytes": stored_bytes,
            "keys": keys,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        buckets = d.pop("buckets")

        objects = d.pop("objects")

        stored_bytes = d.pop("stored_bytes")

        keys = d.pop("keys")

        plan_totals = cls(
            buckets=buckets,
            objects=objects,
            stored_bytes=stored_bytes,
            keys=keys,
        )


        plan_totals.additional_properties = d
        return plan_totals

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
