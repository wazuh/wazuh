# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest

from wazuh.core.exception import WazuhError
from framework.wazuh import kvdb


class FakeEngineClient:
    """Engine client with async mocked methods for catalog and content."""
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
    """Async context manager that yields the FakeEngineClient."""
    def __init__(self, client: FakeEngineClient):
        self.client = client

    async def __aenter__(self):
        return self.client

    async def __aexit__(self, exc_type, exc, tb):
        return False


@pytest.mark.asyncio
async def test_list_kvdbs_ok(monkeypatch):
    """Ensure list_kvdbs queries the engine and processes the array correctly."""
    items_from_engine = {"status": "OK", "content": [{"id": "a", "name": "A"}, {"id": "b", "name": "B"}]}
    processed = {"items": [{"id": "a"}, {"id": "b"}], "totalItems": 2}

    fake = FakeEngineClient()

    # Minimal patches for listing path
    monkeypatch.setattr(kvdb, "get_engine_client", lambda: FakeEngineCM(fake))
    monkeypatch.setattr(kvdb, "validate_response_or_raise", lambda *_args, **_kw: None)
    monkeypatch.setattr(kvdb, "process_array", lambda *_args, **_kw: processed)

    res = await kvdb.list_kvdbs(policy_type="production")

    assert res.affected_items == processed["items"]
    assert res.total_affected_items == processed["totalItems"]
    # Ensure the engine was queried
    fake.content.get_resources.assert_awaited()


@pytest.mark.asyncio
async def test_create_requires_testing_policy():
    """Verify create fails outside 'testing' policy (error 4000)."""
    body = {"type": "kvdb", "id": "100", "name": "demo1", "content": {"k": "v"}}
    with pytest.raises(WazuhError) as exc:
        await kvdb.create_kvdb(policy_type="production", item=body)
    assert getattr(exc.value, "code", None) == 4000


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_body", [
    {"type": "kvdb", "name": "No ID", "content": {"k": "v"}},
    {"type": "kvdb", "id": "100", "name": "Bad content", "content": "not-a-dict"},
])
async def test_create_validates_payload(bad_body):
    """Verify invalid payloads raise error 4000 in create."""
    with pytest.raises(WazuhError) as exc:
        await kvdb.create_kvdb(policy_type="testing", item=bad_body)
    assert getattr(exc.value, "code", None) == 4000


@pytest.mark.asyncio
async def test_create_success(monkeypatch, tmp_path):
    """Create a KVDB successfully and confirm validation and engine calls."""
    body = {"type": "kvdb", "id": "100", "name": "demo1", "content": {"k": "v"}}
    fake = FakeEngineClient()

    # Force asset path into tmp and simulate non-existing file
    asset_path = tmp_path / "100.json"
    monkeypatch.setattr(kvdb, "generate_kvdb_file_path", lambda _id, _pt: str(asset_path))
    monkeypatch.setattr(kvdb, "exists", lambda path: False)

    # File operations as no-ops
    monkeypatch.setattr(kvdb, "save_asset_file", lambda path, payload: None)
    monkeypatch.setattr(kvdb, "remove", lambda path: None)

    # Engine + validations
    monkeypatch.setattr(kvdb, "get_engine_client", lambda: FakeEngineCM(fake))
    monkeypatch.setattr(kvdb, "validate_response_or_raise", lambda *_args, **_kw: None)

    res = await kvdb.create_kvdb(policy_type="testing", item=body)

    assert res.affected_items == ["100"]
    assert res.total_affected_items == 1
    assert res.total_failed_items == 0

    fake.catalog.validate_resource.assert_awaited()
    fake.content.create_resource.assert_awaited()


@pytest.mark.asyncio
async def test_update_requires_testing_policy():
    """Verify update fails outside 'testing' policy (error 4000)."""
    body = {"id": "100", "name": "demo1 (v2)", "content": {"k2": "v2"}}
    with pytest.raises(WazuhError) as exc:
        await kvdb.update_kvdb(policy_type="production", item=body)
    assert getattr(exc.value, "code", None) == 4000


@pytest.mark.asyncio
async def test_update_missing_asset(monkeypatch, tmp_path):
    """Verify update fails when asset file does not exist (error 8005)."""
    body = {"id": "100", "name": "demo1 (v2)", "content": {"k2": "v2"}}

    # Asset file does not exist
    asset_path = tmp_path / "100.json"
    monkeypatch.setattr(kvdb, "generate_kvdb_file_path", lambda _id, _pt: str(asset_path))
    monkeypatch.setattr(kvdb, "exists", lambda path: False)

    with pytest.raises(WazuhError) as exc:
        await kvdb.update_kvdb(policy_type="testing", item=body)
    assert getattr(exc.value, "code", None) == 8005  # Asset does not exist


@pytest.mark.asyncio
async def test_update_success(monkeypatch, tmp_path):
    """Update a KVDB successfully and confirm engine and file ops are called."""
    body = {"id": "100", "name": "demo1 (v2)", "content": {"k2": "v2"}}
    fake = FakeEngineClient()

    # Asset exists
    asset_path = tmp_path / "100.json"
    monkeypatch.setattr(kvdb, "generate_kvdb_file_path", lambda _id, _pt: str(asset_path))
    monkeypatch.setattr(kvdb, "exists", lambda path: True)

    # File operations as no-ops (backup, remove, write, restore)
    monkeypatch.setattr(kvdb, "full_copy", lambda src, dst: None)
    monkeypatch.setattr(kvdb, "remove", lambda path: None)
    monkeypatch.setattr(kvdb, "save_asset_file", lambda path, payload: None)
    monkeypatch.setattr(kvdb, "safe_move", lambda src, dst: None)

    # Engine + validations
    monkeypatch.setattr(kvdb, "get_engine_client", lambda: FakeEngineCM(fake))
    monkeypatch.setattr(kvdb, "validate_response_or_raise", lambda *_args, **_kw: None)

    res = await kvdb.update_kvdb(policy_type="testing", item=body)

    assert res.affected_items == ["100"]
    assert res.total_affected_items == 1
    assert res.total_failed_items == 0

    fake.catalog.validate_resource.assert_awaited()
    fake.content.update_resource.assert_awaited()


@pytest.mark.asyncio
async def test_delete_requires_testing_policy():
    """Verify delete fails outside 'testing' policy (error 4000)."""
    with pytest.raises(WazuhError) as exc:
        await kvdb.delete_kvdbs(policy_type="production", ids=["a", "b"])
    assert getattr(exc.value, "code", None) == 4000


@pytest.mark.asyncio
async def test_delete_missing_asset(monkeypatch, tmp_path):
    """Verify delete reports failures when files do not exist."""
    # Assets do not exist
    monkeypatch.setattr(kvdb, "generate_kvdb_file_path", lambda _id, _pt: str(tmp_path / f"{_id}.json"))
    monkeypatch.setattr(kvdb, "exists", lambda path: False)

    res = await kvdb.delete_kvdbs(policy_type="testing", ids=["a", "b"])

    assert res.total_affected_items == 0
    assert res.affected_items == []
    assert res.total_failed_items == 2


@pytest.mark.asyncio
async def test_delete_ok_calls_engine_per_id(monkeypatch, tmp_path):
    """Verify delete calls the engine once per id and returns affected ids."""
    fake = FakeEngineClient()

    # Assets exist
    monkeypatch.setattr(kvdb, "generate_kvdb_file_path", lambda _id, _pt: str(tmp_path / f"{_id}.json"))
    monkeypatch.setattr(kvdb, "exists", lambda path: True)

    # File operations as no-ops
    monkeypatch.setattr(kvdb, "full_copy", lambda src, dst: None)
    monkeypatch.setattr(kvdb, "remove", lambda path: None)
    monkeypatch.setattr(kvdb, "safe_move", lambda src, dst: None)

    # Engine
    monkeypatch.setattr(kvdb, "get_engine_client", lambda: FakeEngineCM(fake))
    monkeypatch.setattr(kvdb, "validate_response_or_raise", lambda *_args, **_kw: None)

    res = await kvdb.delete_kvdbs(policy_type="testing", ids=["a", "b"])

    assert res.affected_items == ["a", "b"]
    assert res.total_affected_items == 2
    assert res.total_failed_items == 0

    assert fake.content.delete_resource.await_count == 2
