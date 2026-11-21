"""The Python SDK's core against scripted transports: retries, error bodies,
idempotency keys, base URL rules, path arguments and token redaction."""

from __future__ import annotations

import json

import httpx2
import pytest

import kofra._core as core_module
from kofra import Kofra, KofraError

TOKEN = "kofra_tok_secret_value_1"
BUCKET = {
    "name": "backups",
    "created_at": "2026-11-02T08:00:00Z",
    "stored_bytes": 1,
    "object_count": 1,
}
BUSY_409 = {
    "type": "https://kofra.app/docs/errors/idempotency_key_in_use",
    "title": "Same request is still running",
    "status": 409,
    "code": "idempotency_key_in_use",
    "detail": "A request with this Idempotency-Key is still in progress.",
    "hint": "Wait, then send the identical request again with the same key.",
    "docs_url": "https://kofra.app/docs/errors/idempotency_key_in_use.md",
    "request_id": "req_1",
    "retryable": True,
}


class Script:
    """Answers requests from a list of (status, body, headers) or exceptions."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        status, body, headers = answer
        content = body if isinstance(body, bytes) else json.dumps(body).encode()
        return httpx2.Response(status, content=content, headers=headers)


@pytest.fixture
def slept(monkeypatch):
    waits: list[float] = []
    monkeypatch.setattr(core_module.time, "sleep", waits.append)
    return waits


def client(script, **kw):
    kw.setdefault("max_retry_wait", 5)
    return Kofra(token=TOKEN, base_url="https://api.example.test", transport=httpx2.MockTransport(script), **kw)


def test_429_and_503_are_retried_with_the_same_idempotency_key(slept):
    script = Script(
        (429, {"code": "rate_limited", "partial": True}, {"retry-after": "1"}),
        (503, b"<html>busy</html>", {"content-type": "text/html", "retry-after": "2"}),
        (201, BUCKET, {}),
    )
    assert client(script).buckets.create(body={"name": "backups"}).name == "backups"
    assert slept == [1.0, 2.0]
    keys = {r.headers["idempotency-key"] for r in script.requests}
    assert len(script.requests) == 3 and len(keys) == 1


def test_each_call_gets_a_fresh_idempotency_key(slept):
    script = Script((201, BUCKET, {}), (201, BUCKET, {}))
    k = client(script)
    k.buckets.create(body={"name": "backups"})
    k.buckets.create(body={"name": "backups"})
    a, b = (r.headers["idempotency-key"] for r in script.requests)
    assert a and b and a != b


def test_a_409_idempotency_key_in_use_is_retried(slept):
    script = Script((409, BUSY_409, {"retry-after": "1"}), (201, BUCKET, {}))
    assert client(script).buckets.create(body={"name": "backups"}).name == "backups"
    assert len(script.requests) == 2


def test_a_non_json_error_body_is_a_kofra_error(slept):
    script = Script((503, b"<html>down</html>", {"content-type": "text/html"}))
    with pytest.raises(KofraError) as err:
        client(script, max_retries=0).buckets.list()
    assert err.value.status == 503 and err.value.code == "http_503" and err.value.hint


def test_retries_are_bounded(slept):
    script = Script(*[(503, b"", {"retry-after": "0"})] * 3)
    with pytest.raises(KofraError) as err:
        client(script, max_retries=2).buckets.list()
    assert err.value.status == 503 and len(script.requests) == 3


def test_a_retry_after_beyond_the_max_wait_stops_retrying(slept):
    script = Script((429, b"", {"retry-after": "120"}), (200, {"data": [], "next_cursor": None}, {}))
    with pytest.raises(KofraError) as err:
        client(script, max_retry_wait=30).buckets.list()
    assert err.value.status == 429 and len(script.requests) == 1 and slept == []
    script = Script(
        (429, b"", {"retry-after": "Wed, 21 Oct 2099 07:28:00 GMT"}),
        (200, {"data": [], "next_cursor": None}, {}),
    )
    with pytest.raises(KofraError):
        client(script).buckets.list()
    assert len(script.requests) == 1


def test_a_retry_after_http_date_is_honoured(slept):
    from email.utils import format_datetime
    from datetime import datetime, timedelta, timezone

    when = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=3), usegmt=True)
    script = Script((503, b"", {"retry-after": when}), (200, {"data": [], "next_cursor": None}, {}))
    client(script).buckets.list()
    assert len(script.requests) == 2 and 0 < slept[0] <= 3


def test_network_errors_are_retried(slept):
    script = Script(httpx2.ConnectError("refused"), (200, {"data": [], "next_cursor": None}, {}))
    assert client(script).buckets.list().data == []
    assert len(script.requests) == 2


@pytest.mark.parametrize(
    "url",
    ["http://api.example.test", "http://10.0.0.1:8080", "ftp://api.example.test", "api.example.test"],
)
def test_a_non_https_base_url_is_refused(url):
    with pytest.raises(ValueError, match="https"):
        Kofra(token=TOKEN, base_url=url)


@pytest.mark.parametrize("url", ["http://localhost:4010", "http://127.0.0.2:1", "http://[::1]:4010", "https://x.test"])
def test_https_and_loopback_base_urls_are_accepted(url):
    Kofra(token=TOKEN, base_url=url)


def test_plain_http_needs_an_explicit_opt_in():
    Kofra(token=TOKEN, base_url="http://api.example.test", allow_insecure_http=True)


@pytest.mark.parametrize("bad", ["", ".", ".."])
def test_empty_and_dot_path_arguments_are_refused(bad):
    script = Script()
    with pytest.raises(ValueError, match="path"):
        client(script).buckets.get(bad)
    assert script.requests == []


def test_the_token_is_never_in_a_repr():
    k = client(Script())
    for obj in (k, k._core, k._core._client, k.buckets):
        assert TOKEN not in repr(obj)
    assert "redacted" in repr(k._core)
    assert not hasattr(k._core, "client")




def test_unknown_enum_values_in_answers_are_kept(slept):
    from kofra._generated.models.account_state import AccountState

    assert AccountState("archived").value == "archived"
    assert AccountState("active") is AccountState.ACTIVE
    keys = {
        "data": [
            {
                "id": "KF7Q2M8X4T7R5N0B",
                "name": "x",
                "grants": [{"bucket": "backups", "access": "read_only_soon"}],
                "created_at": "2026-11-19T10:00:00Z",
                "last_used_at": None,
            }
        ],
        "next_cursor": None,
    }
    page = client(Script((200, keys, {}))).keys.list()
    assert page.data[0].grants[0].access.value == "read_only_soon"


ACCOUNT = {
    "id": "ws_01jd3k9v6q2m8x4t7r5n0b1c2d",
    "state": "active",
    "access": "full",
    "s3_endpoint": "https://s3.kofra.io",
    "limits": {
        "storage_bytes": 1099511627776,
        "upload_24h_bytes": 214748364800,
        "download_allowance_bytes": 1099511627776,
        "active_keys": 20,
    },
    "suspension": None,
    "deletion": None,
    "created_at": "2026-11-01T09:30:00Z",
}


def test_an_unknown_response_enum_value_reads_as_other_and_keeps_its_value():
    # The contract adds enum values within /v1; a client reads an unknown one as "other".
    body = {**ACCOUNT, "state": "archived", "access": "read_only_plus"}
    account = client(Script((200, body, {}))).account.get()
    assert account.state.name == "OTHER"
    assert account.access.name == "OTHER"
    assert str(account.state) == "archived"
    assert account.state.value == "archived"
    assert account.state != "active"
    assert account.to_dict()["state"] == "archived"
    # Known values are unchanged.
    known = client(Script((200, ACCOUNT, {}))).account.get()
    assert known.state.name == "ACTIVE"


def test_an_unknown_nested_response_enum_value_reads_as_other():
    body = {
        **ACCOUNT,
        "state": "suspended",
        "suspension": {"reason": "fraud_review", "mode": "frozen", "since": "2026-11-02T08:00:00Z"},
    }
    from kofra._generated.models.suspension import Suspension

    s = Suspension.from_dict(body["suspension"])
    assert s.reason.name == "OTHER" and str(s.reason) == "fraud_review"
    assert s.mode.name == "OTHER" and str(s.mode) == "frozen"


def test_request_only_enums_stay_strict():
    from kofra._generated.models.grant_input_access import GrantInputAccess
    from kofra._generated.models.objects_list_delimiter import ObjectsListDelimiter
    from kofra._generated.models.presign_request_method import PresignRequestMethod

    for enum in (GrantInputAccess, ObjectsListDelimiter, PresignRequestMethod):
        with pytest.raises(ValueError):
            enum("not_a_value")


def test_every_generated_enum_but_the_request_only_ones_tolerates_new_values():
    # Catches a single enum losing its hook. A new request-only enum must be
    # added here on purpose.
    import enum
    import importlib
    import pkgutil

    import kofra._generated.models as models

    request_only = {"GrantInputAccess", "ObjectsListDelimiter", "PresignRequestMethod"}
    seen = set()
    for info in pkgutil.iter_modules(models.__path__):
        module = importlib.import_module(f"{models.__name__}.{info.name}")
        for obj in vars(module).values():
            if not (isinstance(obj, type) and issubclass(obj, enum.StrEnum)) or obj is enum.StrEnum:
                continue
            if obj.__module__ != module.__name__:
                continue
            seen.add(obj.__name__)
            if obj.__name__ in request_only:
                with pytest.raises(ValueError):
                    obj("value_added_later")
            else:
                member = obj("value_added_later")
                assert member.name == "OTHER" and str(member) == "value_added_later", obj.__name__
    assert request_only <= seen
    assert len(seen) >= 13
