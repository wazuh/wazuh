# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch, ANY
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
@patch('framework.wazuh.kvdb.process_array')
@patch('framework.wazuh.kvdb.validate_response_or_raise')
@patch('framework.wazuh.kvdb.get_engine_client')
async def test_list_kvdbs_ok(mock_get_client, mock_validate, mock_process):
    """Ensure list_kvdbs queries the engine and processes the array correctly."""
    items_from_engine = {"status": "OK", "content": [{"id": "a", "name": "A"}, {"id": "b", "name": "B"}]}
    processed = {"items": [{"id": "a"}, {"id": "b"}], "totalItems": 2}

    fake = FakeEngineClient(get_resources_return=items_from_engine)
    mock_get_client.return_value = FakeEngineCM(fake)
    mock_process.return_value = processed

    res = await kvdb.list_kvdbs(policy_type="production")

    assert res.affected_items == processed["items"]
    assert res.total_affected_items == processed["totalItems"]
    fake.content.get_resources.assert_awaited()
    mock_validate.assert_called()
    mock_process.assert_called_once()


@pytest.mark.asyncio
async def test_create_requires_testing_policy():
    """Verify create fails outside 'testing' policy (error 1804)."""
    body = {"type": "kvdb", "id": "100", "name": "demo1", "content": {"k": "v"}}
    with pytest.raises(WazuhError) as exc:
        await kvdb.create_kvdb(policy_type="production", item=body)
    assert getattr(exc.value, "code", None) == 1804


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_body", [
    {"type": "kvdb", "name": "No ID", "content": {"k": "v"}},                   # missing id
    {"type": "kvdb", "id": "100", "name": "Bad content", "content": "str"},     # content not dict
])
async def test_create_validates_payload(bad_body):
    """Verify invalid payloads raise error 1806 in create."""
    with pytest.raises(WazuhError) as exc:
        await kvdb.create_kvdb(policy_type="testing", item=bad_body)
    assert getattr(exc.value, "code", None) == 1806


@pytest.mark.asyncio
@patch('framework.wazuh.kvdb.validate_response_or_raise')
@patch('framework.wazuh.kvdb.get_engine_client')
@patch('framework.wazuh.kvdb.remove')
@patch('framework.wazuh.kvdb.save_asset_file')
@patch('framework.wazuh.kvdb.exists', return_value=False)
@patch('framework.wazuh.kvdb.generate_kvdb_file_path')
async def test_create_success(mock_gen_path, mock_exists, mock_save, mock_remove, mock_get_client, mock_validate, tmp_path):
    """Create a KVDB successfully and confirm validation and engine calls."""
    body = {"type": "kvdb", "id": "100", "name": "demo1", "content": {"k": "v"}}
    fake = FakeEngineClient()
    asset_path = tmp_path / "100.json"
    mock_gen_path.return_value = str(asset_path)
    mock_get_client.return_value = FakeEngineCM(fake)

    res = await kvdb.create_kvdb(policy_type="testing", item=body)

    assert res.affected_items == ["100"]
    assert res.total_affected_items == 1
    assert res.total_failed_items == 0

    mock_exists.assert_called()
    mock_save.assert_called_once_with(str(asset_path), ANY)
    fake.catalog.validate_resource.assert_awaited()
    fake.content.create_resource.assert_awaited()


@pytest.mark.asyncio
async def test_update_requires_testing_policy():
    """Verify update fails outside 'testing' policy (error 1804)."""
    body = {"id": "100", "name": "demo1 (v2)", "content": {"k2": "v2"}}
    with pytest.raises(WazuhError) as exc:
        await kvdb.update_kvdb(policy_type="production", item=body)
    assert getattr(exc.value, "code", None) == 1804


@pytest.mark.asyncio
@patch('framework.wazuh.kvdb.exists', return_value=False)
@patch('framework.wazuh.kvdb.generate_kvdb_file_path')
async def test_update_missing_asset(mock_gen_path, mock_exists, tmp_path):
    """Verify update fails when asset file does not exist (error 8005)."""
    body = {"id": "100", "name": "demo1 (v2)", "content": {"k2": "v2"}}
    asset_path = tmp_path / "100.json"
    mock_gen_path.return_value = str(asset_path)

    with pytest.raises(WazuhError) as exc:
        await kvdb.update_kvdb(policy_type="testing", item=body)
    assert getattr(exc.value, "code", None) == 8005


@pytest.mark.asyncio
@patch('framework.wazuh.kvdb.validate_response_or_raise')
@patch('framework.wazuh.kvdb.get_engine_client')
@patch('framework.wazuh.kvdb.safe_move')
@patch('framework.wazuh.kvdb.save_asset_file')
@patch('framework.wazuh.kvdb.remove')
@patch('framework.wazuh.kvdb.full_copy')
@patch('framework.wazuh.kvdb.exists', return_value=True)
@patch('framework.wazuh.kvdb.generate_kvdb_file_path')
async def test_update_success(mock_gen_path, mock_exists, mock_full_copy, mock_remove, mock_save, mock_safe_move, mock_get_client, mock_validate, tmp_path):
    """Update a KVDB successfully and confirm engine and file ops are called."""
    body = {"id": "100", "name": "demo1 (v2)", "content": {"k2": "v2"}}
    fake = FakeEngineClient()
    asset_path = tmp_path / "100.json"
    mock_gen_path.return_value = str(asset_path)
    mock_get_client.return_value = FakeEngineCM(fake)

    res = await kvdb.update_kvdb(policy_type="testing", item=body)

    assert res.affected_items == ["100"]
    assert res.total_affected_items == 1
    assert res.total_failed_items == 0

    # backup created
    mock_full_copy.assert_called_once()
    # original removed and/or backup cleaned
    mock_remove.assert_called()
    mock_save.assert_called_once_with(str(asset_path), ANY)
    fake.catalog.validate_resource.assert_awaited()
    fake.content.update_resource.assert_awaited()


@pytest.mark.asyncio
async def test_delete_requires_testing_policy():
    """Verify delete fails outside 'testing' policy (error 1804)."""
    with pytest.raises(WazuhError) as exc:
        await kvdb.delete_kvdbs(policy_type="production", ids=["a", "b"])
    assert getattr(exc.value, "code", None) == 1804


@pytest.mark.asyncio
@patch('framework.wazuh.kvdb.exists', return_value=False)
@patch('framework.wazuh.kvdb.generate_kvdb_file_path')
async def test_delete_missing_asset(mock_gen_path, mock_exists, tmp_path):
    """Verify delete reports failures when files do not exist."""
    mock_gen_path.side_effect = lambda _id, _pt: str(tmp_path / f"{_id}.json")

    res = await kvdb.delete_kvdbs(policy_type="testing", ids=["a", "b"])

    assert res.total_affected_items == 0
    assert res.affected_items == []
    assert res.total_failed_items == 2


@pytest.mark.asyncio
@patch('framework.wazuh.kvdb.validate_response_or_raise')
@patch('framework.wazuh.kvdb.get_engine_client')
@patch('framework.wazuh.kvdb.safe_move')
@patch('framework.wazuh.kvdb.remove')
@patch('framework.wazuh.kvdb.full_copy')
@patch('framework.wazuh.kvdb.exists', return_value=True)
@patch('framework.wazuh.kvdb.generate_kvdb_file_path')
async def test_delete_ok_calls_engine_per_id(mock_gen_path, mock_exists, mock_full_copy, mock_remove, mock_safe_move, mock_get_client, mock_validate, tmp_path):
    """Verify delete calls the engine once per id and returns affected ids."""
    fake = FakeEngineClient()
    mock_gen_path.side_effect = lambda _id, _pt: str(tmp_path / f"{_id}.json")
    mock_get_client.return_value = FakeEngineCM(fake)

    res = await kvdb.delete_kvdbs(policy_type="testing", ids=["a", "b"])

    assert res.affected_items == ["a", "b"]
    assert res.total_affected_items == 2
    assert res.total_failed_items == 0

    assert fake.content.delete_resource.await_count == 2
