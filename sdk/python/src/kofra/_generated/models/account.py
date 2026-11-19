from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.account_access import AccountAccess
from ..models.account_state import AccountState
from typing import cast
import datetime

if TYPE_CHECKING:
  from ..models.account_limits import AccountLimits
  from ..models.deletion import Deletion
  from ..models.suspension import Suspension





T = TypeVar("T", bound="Account")



@_attrs_define
class Account:
    """ 
        Attributes:
            id (str): The workspace ID.
            state (AccountState): `active`: normal service. `suspended`: see `suspension`. `deleting`:
                a confirmed deletion is in progress; see `deletion`.
            access (AccountAccess): What S3 requests can do now. `read_only` allows reads, lists and deletes.
            s3_endpoint (str): The S3 endpoint for this workspace's buckets.
            limits (AccountLimits):
            suspension (None | Suspension):
            deletion (Deletion | None):
            created_at (datetime.datetime): RFC 3339 timestamp in UTC.
     """

    id: str
    state: AccountState
    access: AccountAccess
    s3_endpoint: str
    limits: AccountLimits
    suspension: None | Suspension
    deletion: Deletion | None
    created_at: datetime.datetime
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        from ..models.account_limits import AccountLimits # noqa: PLC0415
        from ..models.deletion import Deletion # noqa: PLC0415
        from ..models.suspension import Suspension # noqa: PLC0415
        id = self.id

        state = self.state.value

        access = self.access.value

        s3_endpoint = self.s3_endpoint

        limits = self.limits.to_dict()

        suspension: dict[str, Any] | None
        if isinstance(self.suspension, Suspension):
            suspension = self.suspension.to_dict()
        else:
            suspension = self.suspension

        deletion: dict[str, Any] | None
        if isinstance(self.deletion, Deletion):
            deletion = self.deletion.to_dict()
        else:
            deletion = self.deletion

        created_at = self.created_at.isoformat()


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "id": id,
            "state": state,
            "access": access,
            "s3_endpoint": s3_endpoint,
            "limits": limits,
            "suspension": suspension,
            "deletion": deletion,
            "created_at": created_at,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.account_limits import AccountLimits # noqa: PLC0415
        from ..models.deletion import Deletion # noqa: PLC0415
        from ..models.suspension import Suspension # noqa: PLC0415
        d = dict(src_dict)
        id = d.pop("id")

        state = AccountState(d.pop("state"))




        access = AccountAccess(d.pop("access"))




        s3_endpoint = d.pop("s3_endpoint")

        limits = AccountLimits.from_dict(d.pop("limits"))




        def _parse_suspension(data: object) -> None | Suspension:
            if data is None:
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                suspension_type_0 = Suspension.from_dict(data)



                return suspension_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Suspension, data)

        suspension = _parse_suspension(d.pop("suspension"))


        def _parse_deletion(data: object) -> Deletion | None:
            if data is None:
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                deletion_type_0 = Deletion.from_dict(data)



                return deletion_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(Deletion | None, data)

        deletion = _parse_deletion(d.pop("deletion"))


        created_at = datetime.datetime.fromisoformat(d.pop("created_at"))




        account = cls(
            id=id,
            state=state,
            access=access,
            s3_endpoint=s3_endpoint,
            limits=limits,
            suspension=suspension,
            deletion=deletion,
            created_at=created_at,
        )


        account.additional_properties = d
        return account

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
