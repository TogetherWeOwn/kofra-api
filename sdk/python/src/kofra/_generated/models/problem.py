from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
  from ..models.field_error import FieldError





T = TypeVar("T", bound="Problem")



@_attrs_define
class Problem:
    """ RFC 9457 problem details with Kofra's fields. Only `code` is stable.

        Attributes:
            type_ (str): A page describing this error code.
            title (str):
            status (int):
            code (str): Stable machine name; see the error catalogue. New codes may be added within `/v1`.
            detail (str):
            hint (str): What to do next, in one sentence.
            docs_url (str): The Markdown version of the error page.
            request_id (str): Same as the `Kofra-Request-Id` header. Quote it to support.
            retryable (bool): Whether the same request may succeed if repeated (after `Retry-After`, when given).
            errors (list[FieldError] | Unset): Per-field problems, for `validation_failed`, `unknown_field` and similar
                codes.
     """

    type_: str
    title: str
    status: int
    code: str
    detail: str
    hint: str
    docs_url: str
    request_id: str
    retryable: bool
    errors: list[FieldError] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        from ..models.field_error import FieldError # noqa: PLC0415
        type_ = self.type_

        title = self.title

        status = self.status

        code = self.code

        detail = self.detail

        hint = self.hint

        docs_url = self.docs_url

        request_id = self.request_id

        retryable = self.retryable

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)




        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "type": type_,
            "title": title,
            "status": status,
            "code": code,
            "detail": detail,
            "hint": hint,
            "docs_url": docs_url,
            "request_id": request_id,
            "retryable": retryable,
        })
        if errors is not UNSET:
            field_dict["errors"] = errors

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.field_error import FieldError # noqa: PLC0415
        d = dict(src_dict)
        type_ = d.pop("type")

        title = d.pop("title")

        status = d.pop("status")

        code = d.pop("code")

        detail = d.pop("detail")

        hint = d.pop("hint")

        docs_url = d.pop("docs_url")

        request_id = d.pop("request_id")

        retryable = d.pop("retryable")

        _errors = d.pop("errors", UNSET)
        errors: list[FieldError] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = FieldError.from_dict(errors_item_data)



                errors.append(errors_item)


        problem = cls(
            type_=type_,
            title=title,
            status=status,
            code=code,
            detail=detail,
            hint=hint,
            docs_url=docs_url,
            request_id=request_id,
            retryable=retryable,
            errors=errors,
        )


        problem.additional_properties = d
        return problem

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
