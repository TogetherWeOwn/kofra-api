"""The Kofra API client for Python.

    from kofra import Kofra
    kofra = Kofra(token="...")          # or KOFRA_API_TOKEN
    for bucket in kofra.buckets.list().data:
        print(bucket.name)
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

from ._core import Core, KofraError
from ._generated.types import UNSET
from ._operations import (
    RESOURCES,
    AccountApi,
    BucketsApi,
    EventsApi,
    KeysApi,
    ObjectsApi,
    UsageApi,
)

__all__ = ["Kofra", "KofraError", "paginate"]


class Kofra:
    """One client per API token."""

    account: AccountApi
    buckets: BucketsApi
    keys: KeysApi
    usage: UsageApi
    events: EventsApi
    objects: ObjectsApi

    def __init__(
        self,
        token: str | None = None,
        base_url: str | None = None,
        max_retries: int = 2,
        max_retry_wait: float = 30.0,
        timeout: float = 30.0,
        allow_insecure_http: bool = False,
        transport: Any = None,
    ) -> None:
        self._core = Core(token, base_url, max_retries, max_retry_wait, timeout, allow_insecure_http, transport)
        for name, api in RESOURCES.items():
            setattr(self, name, api(self._core))

    def __repr__(self) -> str:
        return f"Kofra(base_url={self._core.base_url!r}, token=<redacted>)"


def paginate(list_fn: Callable[..., Any], **kwargs: Any) -> Iterator[Any]:
    """Every item of a cursor-paged list: `for b in paginate(kofra.buckets.list): ...`.

    Stops at the end of the list, or when a page comes back empty (the event
    feed always returns a cursor to poll from)."""
    while True:
        page = list_fn(**kwargs)
        yield from page.data
        cursor = page.next_cursor
        if cursor in (None, UNSET) or not page.data:
            return
        kwargs["cursor"] = cursor
