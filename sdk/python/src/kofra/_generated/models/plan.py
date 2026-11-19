from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from typing import cast

if TYPE_CHECKING:
  from ..models.plan_effects_item import PlanEffectsItem
  from ..models.plan_totals import PlanTotals





T = TypeVar("T", bound="Plan")



@_attrs_define
class Plan:
    """ The answer to `dry_run=true`. Nothing was changed.

        Attributes:
            dry_run (bool):
            operation (str): The operationId that was planned.
            summary (str): One plain sentence describing the effect.
            reversible (bool): Whether the change could be undone after it is made.
            effects (list[PlanEffectsItem]):
            totals (PlanTotals):
     """

    dry_run: bool
    operation: str
    summary: str
    reversible: bool
    effects: list[PlanEffectsItem]
    totals: PlanTotals
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        from ..models.plan_effects_item import PlanEffectsItem # noqa: PLC0415
        from ..models.plan_totals import PlanTotals # noqa: PLC0415
        dry_run = self.dry_run

        operation = self.operation

        summary = self.summary

        reversible = self.reversible

        effects = []
        for effects_item_data in self.effects:
            effects_item = effects_item_data.to_dict()
            effects.append(effects_item)



        totals = self.totals.to_dict()


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "dry_run": dry_run,
            "operation": operation,
            "summary": summary,
            "reversible": reversible,
            "effects": effects,
            "totals": totals,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.plan_effects_item import PlanEffectsItem # noqa: PLC0415
        from ..models.plan_totals import PlanTotals # noqa: PLC0415
        d = dict(src_dict)
        dry_run = d.pop("dry_run")

        operation = d.pop("operation")

        summary = d.pop("summary")

        reversible = d.pop("reversible")

        effects = []
        _effects = d.pop("effects")
        for effects_item_data in (_effects):
            effects_item = PlanEffectsItem.from_dict(effects_item_data)



            effects.append(effects_item)


        totals = PlanTotals.from_dict(d.pop("totals"))




        plan = cls(
            dry_run=dry_run,
            operation=operation,
            summary=summary,
            reversible=reversible,
            effects=effects,
            totals=totals,
        )


        plan.additional_properties = d
        return plan

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
