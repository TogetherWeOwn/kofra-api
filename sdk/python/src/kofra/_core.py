"""Hand-written core of the Python SDK: authentication, base URL, retries,
idempotency keys and errors. The models and request functions under
`_generated` and the per-operation layer in `_operations.py` are generated
from the contract."""

from __future__ import annotations

import inspect
import os
import time
import typing
import uuid
from typing import Any

import httpx2

from ._generated.client import AuthenticatedClient

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
        import json

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


class Core:
    """Shared by every resource of one client."""

    def __init__(
        self,
        token: str | None = None,
        base_url: str | None = None,
        max_retries: int = 2,
        max_retry_wait: float = 30.0,
        timeout: float = 30.0,
    ) -> None:
        token = token or os.environ.get("KOFRA_API_TOKEN")
        if not token:
            raise ValueError("Kofra: no API token; pass token= or set KOFRA_API_TOKEN.")
        url = (base_url or os.environ.get("KOFRA_API_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.max_retries = max_retries
        self.max_retry_wait = max_retry_wait
        self.client = AuthenticatedClient(
            base_url=url,
            token=token,
            timeout=httpx2.Timeout(timeout),
            raise_on_unexpected_status=False,
        )

    def _wait(self, attempt: int, retry_after: str | None) -> None:
        seconds = float(retry_after) if retry_after and retry_after.isdigit() else 0.5 * 2**attempt
        time.sleep(min(seconds, self.max_retry_wait))

    def call(self, module: Any, *args: Any, **kwargs: Any) -> Any:
        """Runs one generated operation with retries, idempotency and errors."""
        fn = module.sync_detailed
        params = inspect.signature(fn).parameters
        if "idempotency_key" in params and kwargs.get("idempotency_key") is None:
            kwargs["idempotency_key"] = str(uuid.uuid4())
        if "body" in kwargs and isinstance(kwargs["body"], dict):
            body_type = typing.get_type_hints(fn).get("body")
            if hasattr(body_type, "from_dict"):
                raw = kwargs["body"]
                try:
                    model = body_type.from_dict(raw)
                except KeyError as missing:
                    raise ValueError(f"Kofra: body is missing the required field {missing}.") from None
                _refuse_unknown_keys(raw, model.to_dict(), "body")
                kwargs["body"] = model
        for attempt in range(self.max_retries + 1):
            try:
                resp = fn(*args, client=self.client, **kwargs)
            except httpx2.TransportError:
                if attempt >= self.max_retries:
                    raise
                self._wait(attempt, None)
                continue
            status = int(resp.status_code)
            if status in (429, 503) and attempt < self.max_retries:
                self._wait(attempt, resp.headers.get("retry-after"))
                continue
            if 200 <= status < 300:
                return None if status == 204 else resp.parsed
            raise KofraError.from_response(status, resp.content, resp.headers)
        raise AssertionError("unreachable")
