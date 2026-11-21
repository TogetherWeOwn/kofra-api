from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.audit_entry_actor_type import AuditEntryActorType
from ..models.audit_entry_outcome import AuditEntryOutcome
from typing import cast
import datetime






T = TypeVar("T", bound="AuditEntry")



@_attrs_define
class AuditEntry:
    """ 
        Attributes:
            id (str):
            created_at (datetime.datetime): RFC 3339 timestamp in UTC.
            actor_type (AuditEntryActorType): `user`: a member in the console. `token`: an API token. `agent`: an API token
                marked `agent`.
            actor_id (None | str):
            credential_id (None | str): The API token used, if any.
            operation (str): An operation of this API, for example `buckets.create`.
            target (None | str): The bucket, key or token the operation named, if any.
            dry_run (bool):
            outcome (AuditEntryOutcome): `pending`: the request never finished. `refused`: answered with a 4xx. `failed`:
                answered with a 5xx.
            status (int | None):
            code (None | str): The error code of a refused or failed request.
            request_id (str):
            ip (None | str):
            user_agent (None | str):
     """

    id: str
    created_at: datetime.datetime
    actor_type: AuditEntryActorType
    actor_id: None | str
    credential_id: None | str
    operation: str
    target: None | str
    dry_run: bool
    outcome: AuditEntryOutcome
    status: int | None
    code: None | str
    request_id: str
    ip: None | str
    user_agent: None | str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        id = self.id

        created_at = self.created_at.isoformat()

        actor_type = self.actor_type.value

        actor_id: None | str
        actor_id = self.actor_id

        credential_id: None | str
        credential_id = self.credential_id

        operation = self.operation

        target: None | str
        target = self.target

        dry_run = self.dry_run

        outcome = self.outcome.value

        status: int | None
        status = self.status

        code: None | str
        code = self.code

        request_id = self.request_id

        ip: None | str
        ip = self.ip

        user_agent: None | str
        user_agent = self.user_agent


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "id": id,
            "created_at": created_at,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "credential_id": credential_id,
            "operation": operation,
            "target": target,
            "dry_run": dry_run,
            "outcome": outcome,
            "status": status,
            "code": code,
            "request_id": request_id,
            "ip": ip,
            "user_agent": user_agent,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        created_at = datetime.datetime.fromisoformat(d.pop("created_at"))




        actor_type = AuditEntryActorType(d.pop("actor_type"))




        def _parse_actor_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        actor_id = _parse_actor_id(d.pop("actor_id"))


        def _parse_credential_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        credential_id = _parse_credential_id(d.pop("credential_id"))


        operation = d.pop("operation")

        def _parse_target(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        target = _parse_target(d.pop("target"))


        dry_run = d.pop("dry_run")

        outcome = AuditEntryOutcome(d.pop("outcome"))




        def _parse_status(data: object) -> int | None:
            if data is None:
                return data
            return cast(int | None, data)

        status = _parse_status(d.pop("status"))


        def _parse_code(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        code = _parse_code(d.pop("code"))


        request_id = d.pop("request_id")

        def _parse_ip(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        ip = _parse_ip(d.pop("ip"))


        def _parse_user_agent(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        user_agent = _parse_user_agent(d.pop("user_agent"))


        audit_entry = cls(
            id=id,
            created_at=created_at,
            actor_type=actor_type,
            actor_id=actor_id,
            credential_id=credential_id,
            operation=operation,
            target=target,
            dry_run=dry_run,
            outcome=outcome,
            status=status,
            code=code,
            request_id=request_id,
            ip=ip,
            user_agent=user_agent,
        )


        audit_entry.additional_properties = d
        return audit_entry

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
