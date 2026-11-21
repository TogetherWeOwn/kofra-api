from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.scope import Scope
from ..types import UNSET, Unset
from typing import cast






T = TypeVar("T", bound="ApiTokenCreate")



@_attrs_define
class ApiTokenCreate:
    """ 
        Attributes:
            name (str): A label for people; not used for access.
            scopes (list[Scope]): The scopes of a token. Each scope at most once.
            buckets (list[str] | Unset): The only buckets the token can reach. Each bucket at most once.
            allowed_ips (list[str] | Unset): The only client addresses the token is accepted from. Each entry at most once.
            expires_in_days (int | Unset): Days until the token expires. Default 90.
            agent (bool | Unset): Mark the token as used by an AI agent. Default: False.
     """

    name: str
    scopes: list[Scope]
    buckets: list[str] | Unset = UNSET
    allowed_ips: list[str] | Unset = UNSET
    expires_in_days: int | Unset = UNSET
    agent: bool | Unset = False





    def to_dict(self) -> dict[str, Any]:
        name = self.name

        scopes = []
        for componentsschemas_token_scopes_item_data in self.scopes:
            componentsschemas_token_scopes_item = componentsschemas_token_scopes_item_data.value
            scopes.append(componentsschemas_token_scopes_item)



        buckets: list[str] | Unset = UNSET
        if not isinstance(self.buckets, Unset):
            buckets = self.buckets



        allowed_ips: list[str] | Unset = UNSET
        if not isinstance(self.allowed_ips, Unset):
            allowed_ips = self.allowed_ips



        expires_in_days = self.expires_in_days

        agent = self.agent


        field_dict: dict[str, Any] = {}

        field_dict.update({
            "name": name,
            "scopes": scopes,
        })
        if buckets is not UNSET:
            field_dict["buckets"] = buckets
        if allowed_ips is not UNSET:
            field_dict["allowed_ips"] = allowed_ips
        if expires_in_days is not UNSET:
            field_dict["expires_in_days"] = expires_in_days
        if agent is not UNSET:
            field_dict["agent"] = agent

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        scopes = []
        _scopes = d.pop("scopes")
        for componentsschemas_token_scopes_item_data in (_scopes):
            componentsschemas_token_scopes_item = Scope(componentsschemas_token_scopes_item_data)



            scopes.append(componentsschemas_token_scopes_item)


        buckets = cast(list[str], d.pop("buckets", UNSET))


        allowed_ips = cast(list[str], d.pop("allowed_ips", UNSET))


        expires_in_days = d.pop("expires_in_days", UNSET)

        agent = d.pop("agent", UNSET)

        api_token_create = cls(
            name=name,
            scopes=scopes,
            buckets=buckets,
            allowed_ips=allowed_ips,
            expires_in_days=expires_in_days,
            agent=agent,
        )

        return api_token_create

