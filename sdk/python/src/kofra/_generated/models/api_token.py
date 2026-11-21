from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.scope import Scope
from typing import cast
import datetime






T = TypeVar("T", bound="ApiToken")



@_attrs_define
class ApiToken:
    """ 
        Attributes:
            id (str): The API token ID. The token itself is `kofra_tok_`, this ID without `tok_`, `_` and the secret.
            name (str): A label for people; not used for access.
            scopes (list[Scope]):
            buckets (list[str] | None): The only buckets the token can reach; `null` for every bucket the member can reach.
            allowed_ips (list[str] | None): The only client addresses the token is accepted from; `null` for any address.
            agent (bool): The token is used by an AI agent. Shown as such in the audit log; an agent token cannot create
                tokens.
            created_by (str): A member's user ID.
            created_at (datetime.datetime): RFC 3339 timestamp in UTC.
            expires_at (datetime.datetime): RFC 3339 timestamp in UTC.
            last_used_at (datetime.datetime | None): Last accepted request, to within an hour. `null` if never used.
     """

    id: str
    name: str
    scopes: list[Scope]
    buckets: list[str] | None
    allowed_ips: list[str] | None
    agent: bool
    created_by: str
    created_at: datetime.datetime
    expires_at: datetime.datetime
    last_used_at: datetime.datetime | None
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        scopes = []
        for scopes_item_data in self.scopes:
            scopes_item = scopes_item_data.value
            scopes.append(scopes_item)



        buckets: list[str] | None
        if isinstance(self.buckets, list):
            buckets = self.buckets


        else:
            buckets = self.buckets

        allowed_ips: list[str] | None
        if isinstance(self.allowed_ips, list):
            allowed_ips = self.allowed_ips


        else:
            allowed_ips = self.allowed_ips

        agent = self.agent

        created_by = self.created_by

        created_at = self.created_at.isoformat()

        expires_at = self.expires_at.isoformat()

        last_used_at: None | str
        if isinstance(self.last_used_at, datetime.datetime):
            last_used_at = self.last_used_at.isoformat()
        else:
            last_used_at = self.last_used_at


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "id": id,
            "name": name,
            "scopes": scopes,
            "buckets": buckets,
            "allowed_ips": allowed_ips,
            "agent": agent,
            "created_by": created_by,
            "created_at": created_at,
            "expires_at": expires_at,
            "last_used_at": last_used_at,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        scopes = []
        _scopes = d.pop("scopes")
        for scopes_item_data in (_scopes):
            scopes_item = Scope(scopes_item_data)



            scopes.append(scopes_item)


        def _parse_buckets(data: object) -> list[str] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                buckets_type_0 = cast(list[str], data)

                return buckets_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None, data)

        buckets = _parse_buckets(d.pop("buckets"))


        def _parse_allowed_ips(data: object) -> list[str] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                allowed_ips_type_0 = cast(list[str], data)

                return allowed_ips_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None, data)

        allowed_ips = _parse_allowed_ips(d.pop("allowed_ips"))


        agent = d.pop("agent")

        created_by = d.pop("created_by")

        created_at = datetime.datetime.fromisoformat(d.pop("created_at"))




        expires_at = datetime.datetime.fromisoformat(d.pop("expires_at"))




        def _parse_last_used_at(data: object) -> datetime.datetime | None:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                last_used_at_type_0 = datetime.datetime.fromisoformat(data)



                return last_used_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None, data)

        last_used_at = _parse_last_used_at(d.pop("last_used_at"))


        api_token = cls(
            id=id,
            name=name,
            scopes=scopes,
            buckets=buckets,
            allowed_ips=allowed_ips,
            agent=agent,
            created_by=created_by,
            created_at=created_at,
            expires_at=expires_at,
            last_used_at=last_used_at,
        )


        api_token.additional_properties = d
        return api_token

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
