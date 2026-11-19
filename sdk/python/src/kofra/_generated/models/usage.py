from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from typing import cast
import datetime

if TYPE_CHECKING:
  from ..models.usage_downloads import UsageDownloads
  from ..models.usage_open_uploads import UsageOpenUploads
  from ..models.usage_over_limit_type_0 import UsageOverLimitType0
  from ..models.usage_upload_24h import UsageUpload24H





T = TypeVar("T", bound="Usage")



@_attrs_define
class Usage:
    """ 
        Attributes:
            as_of (datetime.datetime): RFC 3339 timestamp in UTC.
            stored_bytes (int):
            object_count (int):
            storage_limit_bytes (int | None):
            over_limit (None | UsageOverLimitType0): Set while stored bytes are above the storage limit.
            upload_24h (UsageUpload24H):
            downloads (UsageDownloads):
            open_uploads (UsageOpenUploads): Multipart uploads started and not yet completed or aborted.
     """

    as_of: datetime.datetime
    stored_bytes: int
    object_count: int
    storage_limit_bytes: int | None
    over_limit: None | UsageOverLimitType0
    upload_24h: UsageUpload24H
    downloads: UsageDownloads
    open_uploads: UsageOpenUploads
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        from ..models.usage_downloads import UsageDownloads # noqa: PLC0415
        from ..models.usage_open_uploads import UsageOpenUploads # noqa: PLC0415
        from ..models.usage_over_limit_type_0 import UsageOverLimitType0 # noqa: PLC0415
        from ..models.usage_upload_24h import UsageUpload24H # noqa: PLC0415
        as_of = self.as_of.isoformat()

        stored_bytes = self.stored_bytes

        object_count = self.object_count

        storage_limit_bytes: int | None
        storage_limit_bytes = self.storage_limit_bytes

        over_limit: dict[str, Any] | None
        if isinstance(self.over_limit, UsageOverLimitType0):
            over_limit = self.over_limit.to_dict()
        else:
            over_limit = self.over_limit

        upload_24h = self.upload_24h.to_dict()

        downloads = self.downloads.to_dict()

        open_uploads = self.open_uploads.to_dict()


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "as_of": as_of,
            "stored_bytes": stored_bytes,
            "object_count": object_count,
            "storage_limit_bytes": storage_limit_bytes,
            "over_limit": over_limit,
            "upload_24h": upload_24h,
            "downloads": downloads,
            "open_uploads": open_uploads,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.usage_downloads import UsageDownloads # noqa: PLC0415
        from ..models.usage_open_uploads import UsageOpenUploads # noqa: PLC0415
        from ..models.usage_over_limit_type_0 import UsageOverLimitType0 # noqa: PLC0415
        from ..models.usage_upload_24h import UsageUpload24H # noqa: PLC0415
        d = dict(src_dict)
        as_of = datetime.datetime.fromisoformat(d.pop("as_of"))




        stored_bytes = d.pop("stored_bytes")

        object_count = d.pop("object_count")

        def _parse_storage_limit_bytes(data: object) -> int | None:
            if data is None:
                return data
            return cast(int | None, data)

        storage_limit_bytes = _parse_storage_limit_bytes(d.pop("storage_limit_bytes"))


        def _parse_over_limit(data: object) -> None | UsageOverLimitType0:
            if data is None:
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                over_limit_type_0 = UsageOverLimitType0.from_dict(data)



                return over_limit_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | UsageOverLimitType0, data)

        over_limit = _parse_over_limit(d.pop("over_limit"))


        upload_24h = UsageUpload24H.from_dict(d.pop("upload_24h"))




        downloads = UsageDownloads.from_dict(d.pop("downloads"))




        open_uploads = UsageOpenUploads.from_dict(d.pop("open_uploads"))




        usage = cls(
            as_of=as_of,
            stored_bytes=stored_bytes,
            object_count=object_count,
            storage_limit_bytes=storage_limit_bytes,
            over_limit=over_limit,
            upload_24h=upload_24h,
            downloads=downloads,
            open_uploads=open_uploads,
        )


        usage.additional_properties = d
        return usage

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
