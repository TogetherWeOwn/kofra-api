from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from typing import cast
import datetime

if TYPE_CHECKING:
  from ..models.event_data import EventData





T = TypeVar("T", bound="Event")



@_attrs_define
class Event:
    """ 
        Attributes:
            id (str):
            type_ (str): `resource.verb_past`, for example `key.created`.
            created_at (datetime.datetime): RFC 3339 timestamp in UTC.
            data (EventData): Event-specific fields. Never holds a secret.
     """

    id: str
    type_: str
    created_at: datetime.datetime
    data: EventData
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        from ..models.event_data import EventData # noqa: PLC0415
        id = self.id

        type_ = self.type_

        created_at = self.created_at.isoformat()

        data = self.data.to_dict()


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "id": id,
            "type": type_,
            "created_at": created_at,
            "data": data,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.event_data import EventData # noqa: PLC0415
        d = dict(src_dict)
        id = d.pop("id")

        type_ = d.pop("type")

        created_at = datetime.datetime.fromisoformat(d.pop("created_at"))




        data = EventData.from_dict(d.pop("data"))




        event = cls(
            id=id,
            type_=type_,
            created_at=created_at,
            data=data,
        )


        event.additional_properties = d
        return event

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
