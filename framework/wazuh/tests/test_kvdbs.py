# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest

from wazuh import kvdbs

class FakeEngineClient:
    """Engine client with async methods in `catalog` and `content`."""
    def __init__(
        self,
        get_resources_return=None,
        validate_return=None,
        create_return=None,
        update_return=None,
        delete_return=None,
    ):
        # Submodules with async functions
        self.catalog = SimpleNamespace(
            validate_resource=AsyncMock(return_value=validate_return or {"status": "OK"})
        )
        self.content = SimpleNamespace(
            get_resources=AsyncMock(return_value=get_resources_return or {"status": "OK", "content": []}),
            create_resource=AsyncMock(return_value=create_return or {"status": "OK"}),
            update_resource=AsyncMock(return_value=update_return or {"status": "OK"}),
            delete_resource=AsyncMock(return_value=delete_return or {"status": "OK"}),
        )


class FakeEngineCM:
    """Async context manager that yields our fake engine client."""
    def __init__(self, client: FakeEngineClient):
        self.client = client

    async def __aenter__(self):
        return self.client

    async def __aexit__(self, exc_type, exc, tb):
        return False


@pytest.mark.asyncio
async def test_list_kvdbs_ok(monkeypatch):
    items_from_engine = {"status": "OK", "content": [{"id": "a", "name": "A"}, {"id": "b", "name": "B"}]}
    processed = {"items": [{"id": "a"}, {"id": "b"}], "totalItems": 2}

    fake = FakeEngineClient(get_resources_return=items_from_engine)

    # Minimal patches for listing
    monkeypatch.setattr(kvdbs, "get_engine_client", lambda: FakeEngineCM(fake))
    monkeypatch.setattr(kvdbs, "validate_response_or_raise", lambda *_args, **_kw: None)
    monkeypatch.setattr(kvdbs, "process_array", lambda *_args, **_kw: processed)

    res = await kvdbs.list_kvdbs(policy_type="production")

    assert res.affected_items == processed["items"]
    assert res.total_affected_items == processed["totalItems"]
    # Ensure the engine was queried
    fake.content.get_resources.assert_awaited()


@pytest.mark.asyncio
async def test_create_requires_testing_policy():
    body = {"type": "kvdb", "id": "100", "name": "demo1", "content": {"k": "v"}}
    res = await kvdbs.create_kvdb(policy_type="production", item=body)

    assert res.total_affected_items == 0
    assert res.affected_items == []
    assert res.total_failed_items == 1  # policy guard


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_body", [
    {"type": "kvdb", "name": "No ID", "content": {"k": "v"}},
    {"type": "kvdb", "id": "100", "name": "Bad content", "content": "not-a-dict"},
])
async def test_create_validates_payload(bad_body):
    res = await kvdbs.create_kvdb(policy_type="testing", item=bad_body)
    assert res.total_affected_items == 0
    assert res.affected_items == []
    assert res.total_failed_items == 1


@pytest.mark.asyncio
async def test_create_success(monkeypatch, tmp_path):
    body = {"type": "kvdb", "id": "100", "name": "demo1", "content": {"k": "v"}}
    fake = FakeEngineClient()

    # Force asset path under tmp and simulate non-existing file
    asset_path = tmp_path / "100.json"
    monkeypatch.setattr(kvdbs, "generate_asset_file_path", lambda _id, _pt: str(asset_path))
    monkeypatch.setattr(kvdbs, "exists", lambda path: False)

    # File operations as no-ops
    monkeypatch.setattr(kvdbs, "save_asset_file", lambda path, payload: None)
    monkeypatch.setattr(kvdbs, "remove", lambda path: None)

    # Engine + validations
    monkeypatch.setattr(kvdbs, "get_engine_client", lambda: FakeEngineCM(fake))
    monkeypatch.setattr(kvdbs, "validate_response_or_raise", lambda *_args, **_kw: None)

    res = await kvdbs.create_kvdb(policy_type="testing", item=body)

    assert res.affected_items == ["100"]
    assert res.total_affected_items == 1
    assert res.total_failed_items == 0

    fake.catalog.validate_resource.assert_awaited()
    fake.content.create_resource.assert_awaited()


@pytest.mark.asyncio
async def test_update_requires_testing_policy():
    body = {"id": "100", "name": "demo1 (v2)", "content": {"k2": "v2"}}
    res = await kvdbs.update_kvdb(policy_type="production", item=body)

    assert res.total_affected_items == 0
    assert res.affected_items == []
    assert res.total_failed_items == 1


@pytest.mark.asyncio
async def test_update_missing_asset(monkeypatch, tmp_path):
    body = {"id": "100", "name": "demo1 (v2)", "content": {"k2": "v2"}}

    # Asset file does not exist
    asset_path = tmp_path / "100.json"
    monkeypatch.setattr(kvdbs, "generate_asset_file_path", lambda _id, _pt: str(asset_path))
    monkeypatch.setattr(kvdbs, "exists", lambda path: False)

    res = await kvdbs.update_kvdb(policy_type="testing", item=body)

    assert res.total_affected_items == 0
    assert res.affected_items == []
    assert res.total_failed_items == 1  # 8005 expected


@pytest.mark.asyncio
async def test_update_success(monkeypatch, tmp_path):
    body = {"id": "100", "name": "demo1 (v2)", "content": {"k2": "v2"}}
    fake = FakeEngineClient()

    # Asset exists
    asset_path = tmp_path / "100.json"
    monkeypatch.setattr(kvdbs, "generate_asset_file_path", lambda _id, _pt: str(asset_path))
    monkeypatch.setattr(kvdbs, "exists", lambda path: True)

    # File operations as no-ops (backup, remove, write, restore)
    monkeypatch.setattr(kvdbs, "full_copy", lambda src, dst: None)
    monkeypatch.setattr(kvdbs, "remove", lambda path: None)
    monkeypatch.setattr(kvdbs, "save_asset_file", lambda path, payload: None)
    monkeypatch.setattr(kvdbs, "safe_move", lambda src, dst: None)

    # Engine + validations
    monkeypatch.setattr(kvdbs, "get_engine_client", lambda: FakeEngineCM(fake))
    monkeypatch.setattr(kvdbs, "validate_response_or_raise", lambda *_args, **_kw: None)

    res = await kvdbs.update_kvdb(policy_type="testing", item=body)

    assert res.affected_items == ["100"]
    assert res.total_affected_items == 1
    assert res.total_failed_items == 0

    fake.catalog.validate_resource.assert_awaited()
    fake.content.update_resource.assert_awaited()


@pytest.mark.asyncio
async def test_delete_requires_testing_policy():
    res = await kvdbs.delete_kvdbs(policy_type="production", ids=["a", "b"])
    assert res.total_affected_items == 0
    assert res.affected_items == []
    assert res.total_failed_items == 2


@pytest.mark.asyncio
async def test_delete_missing_asset(monkeypatch, tmp_path):
    # Assets do not exist
    monkeypatch.setattr(kvdbs, "generate_asset_file_path", lambda _id, _pt: str(tmp_path / f"{_id}.json"))
    monkeypatch.setattr(kvdbs, "exists", lambda path: False)

    res = await kvdbs.delete_kvdbs(policy_type="testing", ids=["a", "b"])

    assert res.total_affected_items == 0
    assert res.affected_items == []
    assert res.total_failed_items == 2


@pytest.mark.asyncio
async def test_delete_ok_calls_engine_per_id(monkeypatch, tmp_path):
    fake = FakeEngineClient()

    # Assets exist
    monkeypatch.setattr(kvdbs, "generate_asset_file_path", lambda _id, _pt: str(tmp_path / f"{_id}.json"))
    monkeypatch.setattr(kvdbs, "exists", lambda path: True)

    # File operations as no-ops
    monkeypatch.setattr(kvdbs, "full_copy", lambda src, dst: None)
    monkeypatch.setattr(kvdbs, "remove", lambda path: None)
    monkeypatch.setattr(kvdbs, "safe_move", lambda src, dst: None)

    # Engine
    monkeypatch.setattr(kvdbs, "get_engine_client", lambda: FakeEngineCM(fake))
    monkeypatch.setattr(kvdbs, "validate_response_or_raise", lambda *_args, **_kw: None)

    res = await kvdbs.delete_kvdbs(policy_type="testing", ids=["a", "b"])

    assert res.affected_items == ["a", "b"]
    assert res.total_affected_items == 2
    assert res.total_failed_items == 0

    assert fake.content.delete_resource.await_count == 2

