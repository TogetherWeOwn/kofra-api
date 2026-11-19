"""Hand-written core of the Python SDK: authentication, base URL, retries,
idempotency keys and errors. The models and request functions under
`_generated` and the per-operation layer in `_operations.py` are generated
from the contract."""

from __future__ import annotations

import inspect
import ipaddress
import json
import os
import time
import typing
import uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlsplit

import httpx2

from ._generated.client import Client

DEFAULT_BASE_URL = "https://api.kofra.app"


class KofraError(Exception):
    """Any non-2xx answer. Branch on `code`; `hint` says what to do next."""

    def __init__(self, problem: dict[str, Any]) -> None:
        super().__init__(f"{problem.get('code')}: {problem.get('detail')}")
        self.problem = problem
        self.status: int = int(problem.get("status", 0))
        self.code: str = str(problem.get("code", ""))
        self.hint: str = str(problem.get("hint", ""))
        self.docs_url: str = str(problem.get("docs_url", ""))
        self.request_id: str = str(problem.get("request_id", ""))
        self.retryable: bool = bool(problem.get("retryable", False))

    @classmethod
    def from_response(cls, status: int, content: bytes, headers: Any) -> KofraError:
        try:
            body = json.loads(content or b"null")
            if isinstance(body, dict) and isinstance(body.get("code"), str):
                return cls(body)
        except ValueError:
            pass
        return cls(
            {
                "type": "about:blank",
                "title": "HTTP error",
                "status": status,
                "code": f"http_{status}",
                "detail": f"The API answered HTTP {status} without a problem body.",
                "hint": "Retry later; if it persists, contact support with the Kofra-Request-Id header.",
                "docs_url": "https://kofra.app/docs/errors/index.md",
                "request_id": headers.get("kofra-request-id", "") if headers else "",
                "retryable": status in (429, 503),
            }
        )


def _refuse_unknown_keys(sent: Any, kept: Any, path: str) -> None:
    """The generated models silently drop keys they do not know. A typo such
    as `nmae` would then vanish without an error, so refuse it here: any key
    of the caller's dict that does not survive the model round trip."""
    if isinstance(sent, dict) and isinstance(kept, dict):
        for key, value in sent.items():
            if key not in kept:
                raise ValueError(f"Kofra: unknown field {path}.{key}; check the spelling against the API reference.")
            _refuse_unknown_keys(value, kept[key], f"{path}.{key}")
    elif isinstance(sent, list) and isinstance(kept, list):
        for i, (a, b) in enumerate(zip(sent, kept)):
            _refuse_unknown_keys(a, b, f"{path}[{i}]")


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _check_base_url(url: str, allow_insecure_http: bool) -> None:
    """https only, except a loopback host (a local mock or proxy), unless the
    caller opts in to plain http explicitly."""
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return
    if parts.scheme == "http" and parts.hostname and (allow_insecure_http or _is_loopback(parts.hostname)):
        return
    raise ValueError(
        f"Kofra: the base URL {url!r} must use https (plain http only for localhost, 127.0.0.0/8 or ::1, "
        "or with allow_insecure_http=True)."
    )


def _check_path_args(args: tuple[Any, ...]) -> None:
    for value in args:
        if str(value) in ("", ".", ".."):
            raise ValueError(f"Kofra: {str(value)!r} is not a valid path argument.")


def _retry_after_seconds(value: str | None) -> float | None:
    """Seconds from a Retry-After header: delta-seconds or an HTTP date."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max((when - datetime.now(timezone.utc)).total_seconds(), 0.0)


def _is_retryable(response: httpx2.Response) -> bool:
    if response.status_code in (429, 503):
        return True
    if response.status_code == 409:
        try:
            body = json.loads(response.content or b"null")
        except ValueError:
            return False
        return isinstance(body, dict) and body.get("code") == "idempotency_key_in_use"
    return False


class Core:
    """Shared by every resource of one client. The token lives only in the
    private HTTP client's headers and never appears in a repr."""

    def __init__(
        self,
        token: str | None = None,
        base_url: str | None = None,
        max_retries: int = 2,
        max_retry_wait: float = 30.0,
        timeout: float = 30.0,
        allow_insecure_http: bool = False,
        transport: httpx2.BaseTransport | None = None,
    ) -> None:
        token = token or os.environ.get("KOFRA_API_TOKEN")
        if not token:
            raise ValueError("Kofra: no API token; pass token= or set KOFRA_API_TOKEN.")
        url = (base_url or os.environ.get("KOFRA_API_URL") or DEFAULT_BASE_URL).rstrip("/")
        _check_base_url(url, allow_insecure_http)
        self.base_url = url
        self.max_retries = max(0, max_retries)
        self.max_retry_wait = max_retry_wait
        self._client = httpx2.Client(
            base_url=url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=httpx2.Timeout(timeout),
            transport=transport,
        )
        # Used only to parse 2xx answers; it carries no token.
        self._parse_client = Client(base_url=url, raise_on_unexpected_status=False)

    def __repr__(self) -> str:
        return f"Core(base_url={self.base_url!r}, token=<redacted>)"

    def _backoff(self, attempt: int, retry_after: str | None) -> float | None:
        """Seconds to wait before the next attempt, or None to stop retrying
        because the server asks for longer than max_retry_wait."""
        asked = _retry_after_seconds(retry_after)
        if asked is not None:
            return asked if asked <= self.max_retry_wait else None
        return min(0.5 * 2**attempt, self.max_retry_wait)

    def call(self, module: Any, *args: Any, **kwargs: Any) -> Any:
        """Runs one generated operation: builds the request with the module's
        `_get_kwargs`, sends it with retries, and parses only 2xx answers."""
        _check_path_args(args)
        params = inspect.signature(module._get_kwargs).parameters
        if "idempotency_key" in params and kwargs.get("idempotency_key") is None:
            kwargs["idempotency_key"] = str(uuid.uuid4())
        if "body" in kwargs and isinstance(kwargs["body"], dict):
            body_type = typing.get_type_hints(module._get_kwargs).get("body")
            if hasattr(body_type, "from_dict"):
                raw = kwargs["body"]
                try:
                    model = body_type.from_dict(raw)
                except KeyError as missing:
                    raise ValueError(f"Kofra: body is missing the required field {missing}.") from None
                _refuse_unknown_keys(raw, model.to_dict(), "body")
                kwargs["body"] = model
        request = module._get_kwargs(*args, **kwargs)
        for attempt in range(self.max_retries + 1):
            last = attempt >= self.max_retries
            try:
                response = self._client.request(**request)
            except httpx2.TransportError:
                if last:
                    raise
                time.sleep(min(0.5 * 2**attempt, self.max_retry_wait))
                continue
            status = response.status_code
            if 200 <= status < 300:
                if status == 204 or not response.content:
                    return None
                return module._parse_response(client=self._parse_client, response=response)
            if not last and _is_retryable(response):
                wait = self._backoff(attempt, response.headers.get("retry-after"))
                if wait is not None:
                    time.sleep(wait)
                    continue
            raise KofraError.from_response(status, response.content, response.headers)
        raise AssertionError("unreachable")
