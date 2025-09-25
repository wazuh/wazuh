# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from types import SimpleNamespace
from unittest.mock import patch
import pytest

from wazuh import kvdbs


class FakeClient:
    """Fake Engine client with a programmable run() script."""
    def __init__(self, script=None):
        # script: list of values/exceptions to yield per run() call
        self._script = list(script or [])
        self.content = SimpleNamespace(
            get_resources=lambda **kwargs: ("GET", kwargs),
            update_resource=lambda **kwargs: ("UPDATE", kwargs),
            create_resource=lambda **kwargs: ("CREATE", kwargs),
            delete_resource=lambda **kwargs: ("DELETE", kwargs),
        )

    def run(self, _):
        if self._script:
            action = self._script.pop(0)
            if isinstance(action, Exception):
                raise action
            return action
        return {}


class _CM:
    """Context manager that yields our fake client."""
    def __init__(self, client):
        self.client = client
    def __enter__(self):
        return self.client
    def __exit__(self, exc_type, exc, tb):
        return False


@pytest.mark.parametrize("items_from_engine, processed", [
    (
        {"content": [{"id": "a", "name": "A"}, {"id": "b", "name": "B"}]},
        {"items": [{"id": "a"}, {"id": "b"}], "totalItems": 2},
    )
])
def test_list_kvdbs_ok(items_from_engine, processed):
    fake = FakeClient(script=[items_from_engine])

    with patch('wazuh.kvdbs.get_engine_client', return_value=_CM(fake)), \
         patch('wazuh.kvdbs.process_array', return_value=processed):
        res = kvdbs.list_kvdbs(policy_type="production")

    assert res.affected_items == processed["items"]
    assert res.total_affected_items == processed["totalItems"]


def test_upsert_requires_testing_policy():
    body = {"type": "kvdb", "id": "x", "name": "X", "content": {"k": "v"}}
    res = kvdbs.upsert_kvdb(policy_type="production", item=body)
    # No Engine calls, just guard failure
    assert res.total_affected_items == 0
    assert res.affected_items == []
    assert res.total_failed_items == 1


@pytest.mark.parametrize("bad_body", [
    {"type": "kvdb", "name": "No ID", "content": {"k": "v"}},
    {"type": "kvdb", "id": "x", "name": "Bad content", "content": "not-a-dict"},
])
def test_upsert_validates_payload(bad_body):
    res = kvdbs.upsert_kvdb(policy_type="testing", item=bad_body)
    assert res.total_affected_items == 0
    assert res.affected_items == []
    assert res.total_failed_items == 1


def test_upsert_update_then_create_path():
    fake = FakeClient(script=[Exception("not found"), {"status": "OK"}])
    body = {"type": "kvdb", "id": "demo1", "name": "Demo", "content": {"k": "v"}}

    with patch('wazuh.kvdbs.get_engine_client', return_value=_CM(fake)):
        res = kvdbs.upsert_kvdb(policy_type="testing", item=body)

    assert res.affected_items == ["demo1"]
    assert res.total_affected_items == 1
    assert res.total_failed_items == 0


def test_delete_requires_testing_policy():
    res = kvdbs.delete_kvdbs(policy_type="production", ids=["a", "b"])
    assert res.total_affected_items == 0
    assert res.affected_items == []
    # one failure per id
    assert res.total_failed_items == 2


def test_delete_ok_calls_engine_per_id():
    fake = FakeClient(script=[{"status": "OK"}, {"status": "OK"}])

    with patch('wazuh.kvdbs.get_engine_client', return_value=_CM(fake)):
        res = kvdbs.delete_kvdbs(policy_type="testing", ids=["a", "b"])

    assert res.affected_items == ["a", "b"]
    assert res.total_affected_items == 2
    assert res.total_failed_items == 0

