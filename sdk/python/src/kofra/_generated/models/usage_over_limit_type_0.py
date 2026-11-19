from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from typing import cast
import datetime






T = TypeVar("T", bound="UsageOverLimitType0")



@_attrs_define
class UsageOverLimitType0:
    """ 
        Attributes:
            since (datetime.datetime): RFC 3339 timestamp in UTC.
            deadline_at (datetime.datetime | None): When writes stop unless usage is reduced or the limit raised. `null` if
                no deadline applies.
     """

    since: datetime.datetime
    deadline_at: datetime.datetime | None
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        since = self.since.isoformat()

        deadline_at: None | str
        if isinstance(self.deadline_at, datetime.datetime):
            deadline_at = self.deadline_at.isoformat()
        else:
            deadline_at = self.deadline_at


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "since": since,
            "deadline_at": deadline_at,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        since = datetime.datetime.fromisoformat(d.pop("since"))




        def _parse_deadline_at(data: object) -> datetime.datetime | None:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                deadline_at_type_0 = datetime.datetime.fromisoformat(data)



                return deadline_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None, data)

        deadline_at = _parse_deadline_at(d.pop("deadline_at"))


        usage_over_limit_type_0 = cls(
            since=since,
            deadline_at=deadline_at,
        )


        usage_over_limit_type_0.additional_properties = d
        return usage_over_limit_type_0

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
