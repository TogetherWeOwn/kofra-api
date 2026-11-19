from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from typing import cast






T = TypeVar("T", bound="AccountLimits")



@_attrs_define
class AccountLimits:
    """ 
        Attributes:
            storage_bytes (int | None): Most bytes the workspace may store. `null` means no fixed limit.
            upload_24h_bytes (int | None): Most bytes that may be uploaded in any 24 hours. `null` means no fixed limit.
            download_allowance_bytes (int | None): Bytes that may be downloaded per billing period. `null` means no fixed
                allowance.
            active_keys (int): Most active S3 access keys at once.
     """

    storage_bytes: int | None
    upload_24h_bytes: int | None
    download_allowance_bytes: int | None
    active_keys: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        storage_bytes: int | None
        storage_bytes = self.storage_bytes

        upload_24h_bytes: int | None
        upload_24h_bytes = self.upload_24h_bytes

        download_allowance_bytes: int | None
        download_allowance_bytes = self.download_allowance_bytes

        active_keys = self.active_keys


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "storage_bytes": storage_bytes,
            "upload_24h_bytes": upload_24h_bytes,
            "download_allowance_bytes": download_allowance_bytes,
            "active_keys": active_keys,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        def _parse_storage_bytes(data: object) -> int | None:
            if data is None:
                return data
            return cast(int | None, data)

        storage_bytes = _parse_storage_bytes(d.pop("storage_bytes"))


        def _parse_upload_24h_bytes(data: object) -> int | None:
            if data is None:
                return data
            return cast(int | None, data)

        upload_24h_bytes = _parse_upload_24h_bytes(d.pop("upload_24h_bytes"))


        def _parse_download_allowance_bytes(data: object) -> int | None:
            if data is None:
                return data
            return cast(int | None, data)

        download_allowance_bytes = _parse_download_allowance_bytes(d.pop("download_allowance_bytes"))


        active_keys = d.pop("active_keys")

        account_limits = cls(
            storage_bytes=storage_bytes,
            upload_24h_bytes=upload_24h_bytes,
            download_allowance_bytes=download_allowance_bytes,
            active_keys=active_keys,
        )


        account_limits.additional_properties = d
        return account_limits

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
