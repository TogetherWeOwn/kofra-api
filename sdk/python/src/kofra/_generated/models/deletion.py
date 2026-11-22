from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.deletion_reason import DeletionReason
from ..models.deletion_status import DeletionStatus
from typing import cast
import datetime






T = TypeVar("T", bound="Deletion")



@_attrs_define
class Deletion:
    """ 
        Attributes:
            status (DeletionStatus): `pending_confirmation`: an Owner must confirm at `confirm_url`
                before `confirm_by`, or the request lapses. `scheduled`: confirmed;
                the data is erased at `erase_at` unless cancelled first.
            reason (DeletionReason): Who started the deletion: `customer` (a member of the account),
                `non_payment`, or `other` (Kofra, for example under the terms of
                service). Only a `customer` deletion can be cancelled through the
                API or the console.
            requested_at (datetime.datetime): RFC 3339 timestamp in UTC.
            confirm_url (None | str): Console page where a signed-in Owner confirms. `null` once confirmed.
            confirm_by (datetime.datetime | None):
            erase_at (datetime.datetime | None): When the data is cryptographically erased. `null` until confirmed.
     """

    status: DeletionStatus
    reason: DeletionReason
    requested_at: datetime.datetime
    confirm_url: None | str
    confirm_by: datetime.datetime | None
    erase_at: datetime.datetime | None
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        status = self.status.value

        reason = self.reason.value

        requested_at = self.requested_at.isoformat()

        confirm_url: None | str
        confirm_url = self.confirm_url

        confirm_by: None | str
        if isinstance(self.confirm_by, datetime.datetime):
            confirm_by = self.confirm_by.isoformat()
        else:
            confirm_by = self.confirm_by

        erase_at: None | str
        if isinstance(self.erase_at, datetime.datetime):
            erase_at = self.erase_at.isoformat()
        else:
            erase_at = self.erase_at


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "status": status,
            "reason": reason,
            "requested_at": requested_at,
            "confirm_url": confirm_url,
            "confirm_by": confirm_by,
            "erase_at": erase_at,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        status = DeletionStatus(d.pop("status"))




        reason = DeletionReason(d.pop("reason"))




        requested_at = datetime.datetime.fromisoformat(d.pop("requested_at"))




        def _parse_confirm_url(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        confirm_url = _parse_confirm_url(d.pop("confirm_url"))


        def _parse_confirm_by(data: object) -> datetime.datetime | None:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                confirm_by_type_0 = datetime.datetime.fromisoformat(data)



                return confirm_by_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None, data)

        confirm_by = _parse_confirm_by(d.pop("confirm_by"))


        def _parse_erase_at(data: object) -> datetime.datetime | None:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                erase_at_type_0 = datetime.datetime.fromisoformat(data)



                return erase_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None, data)

        erase_at = _parse_erase_at(d.pop("erase_at"))


        deletion = cls(
            status=status,
            reason=reason,
            requested_at=requested_at,
            confirm_url=confirm_url,
            confirm_by=confirm_by,
            erase_at=erase_at,
        )


        deletion.additional_properties = d
        return deletion

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
