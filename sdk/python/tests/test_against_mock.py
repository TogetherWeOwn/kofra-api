"""The Python SDK against the contract's mock server (started with Node)."""

from __future__ import annotations

import pathlib
import re
import subprocess

import pytest

from kofra import Kofra, KofraError, paginate

ROOT = pathlib.Path(__file__).resolve().parents[3]


@pytest.fixture(scope="session")
def base_url():
    proc = subprocess.Popen(
        ["node", str(ROOT / "tools/mock/server.mjs"), "--port", "0"],
        stdout=subprocess.PIPE,
        text=True,
    )
    line = proc.stdout.readline()
    match = re.search(r"http://[0-9.]+:\d+", line)
    assert match, line
    yield match.group(0)
    proc.terminate()
    proc.wait(timeout=10)


@pytest.fixture
def kofra(base_url):
    return Kofra(token="kofra_tok_test_1", base_url=base_url, max_retry_wait=0)


def test_every_operation_returns_the_contract_example(kofra):
    assert kofra.account.get().state.value == "active"
    assert len(kofra.buckets.list().data) == 2
    assert kofra.buckets.create(body={"name": "backups"}).name == "backups"
    assert kofra.buckets.get("backups").object_count == 1204
    assert kofra.buckets.delete("old-logs") is None
    assert kofra.keys.list().data[0].id == "KF7Q2M8X4T7R5N0B"
    created = kofra.keys.create(body={"grants": [{"bucket": "backups", "access": "read_write"}]})
    assert created.secret_access_key
    assert len(kofra.keys.update("KF7Q2M8X4T7R5N0B", body={"name": "x"}).grants) == 2
    assert kofra.keys.revoke("KF7Q2M8X4T7R5N0B") is None
    assert kofra.usage.get().object_count == 18342
    assert len(kofra.usage.days().data) == 2
    assert len(kofra.usage.buckets().data) == 2
    assert kofra.events.list().data[0].type_ == "key.created"
    assert kofra.objects.presign(body={"bucket": "backups", "key": "a.txt", "method": "GET"}).url
    assert kofra.account.delete().status.value == "pending_confirmation"
    assert kofra.account.cancel_deletion().state.value == "active"


def test_dry_run_returns_the_plan(kofra):
    plan = kofra.buckets.delete("old-logs", dry_run=True)
    assert plan.dry_run is True and plan.operation == "buckets.delete"


def test_errors_carry_the_catalogue_code_and_hint(kofra, base_url):
    with pytest.raises(KofraError) as err:
        kofra.buckets.get("Bad_Name")
    assert err.value.code == "validation_failed" and err.value.status == 400
    assert err.value.hint and err.value.request_id.startswith("req_")
    readonly = Kofra(token="kofra_tok_ci_readonly", base_url=base_url)
    with pytest.raises(KofraError) as err:
        readonly.buckets.create(body={"name": "backups"})
    assert err.value.code == "insufficient_scope"


def test_unknown_fields_are_refused_before_or_by_the_server(kofra):
    with pytest.raises((KofraError, TypeError, KeyError)):
        kofra.buckets.create(body={"name": "backups", "nmae": "x"})


def test_paginate_walks_a_list(kofra):
    assert [b.name for b in paginate(kofra.buckets.list)] == ["backups", "photos"]


def test_a_missing_token_is_refused(monkeypatch, base_url):
    monkeypatch.delenv("KOFRA_API_TOKEN", raising=False)
    with pytest.raises(ValueError, match="KOFRA_API_TOKEN"):
        Kofra(base_url=base_url)
