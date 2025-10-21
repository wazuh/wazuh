import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from wazuh import WazuhError, integration
from wazuh.core.engine.models.resources import Status
from wazuh.core.results import AffectedItemsWazuhResult


@pytest.mark.asyncio
@patch("wazuh.integration.Resource.from_dict")
@patch("wazuh.integration.generate_asset_file_path", return_value="/fake/path/integration.json")
@patch("wazuh.integration.exists", return_value=False)
@patch("wazuh.integration.save_asset_file")
@patch("wazuh.integration.get_engine_client")
async def test_upsert_integration_create_success(mock_get_engine, mock_save, mock_exists, mock_path, mock_resource):
    """Test creating a new integration successfully."""
    mock_catalog = AsyncMock()
    mock_catalog.validate_resource.return_value = {"status": "OK"}

    mock_content = AsyncMock()
    mock_content.create_resource.return_value = {"status": "OK"}

    mock_client = AsyncMock()
    mock_client.catalog = mock_catalog
    mock_client.content = mock_content

    mock_get_engine.return_value.__aenter__.return_value = mock_client

    fake_resource = MagicMock()
    fake_resource.id = "my_integration"
    mock_resource.return_value = fake_resource

    result = await integration.upsert_integration({"id": "my_integration"}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == ["my_integration"]
    assert result.total_affected_items == 1


@pytest.mark.asyncio
@patch("wazuh.integration.Resource.from_dict", side_effect=WazuhError(9006))
async def test_upsert_integration_bad_format(mock_resource):
    """Test handling bad integration input."""
    result = await integration.upsert_integration({}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == []
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.integration.Resource.from_dict")
@patch("wazuh.integration.generate_asset_file_path", return_value="/fake/path/integration.json")
@patch("wazuh.integration.exists", side_effect=[True, False])
@patch("wazuh.integration.save_asset_file")
@patch("wazuh.integration.get_engine_client")
@patch("wazuh.integration.full_copy")
@patch("wazuh.integration.remove")
@patch("wazuh.integration.safe_move")
async def test_upsert_integration_update_success(
    mock_safe_move,
    mock_remove,
    mock_full_copy,
    mock_get_engine,
    mock_save,
    mock_exists,
    mock_path,
    mock_resource,
):
    """Test updating an existing integration successfully."""
    mock_catalog = AsyncMock()
    mock_catalog.validate_resource.return_value = {"status": "OK"}

    mock_content = AsyncMock()
    mock_content.update_resource.return_value = {"status": "OK"}

    mock_client = AsyncMock()
    mock_client.catalog = mock_catalog
    mock_client.content = mock_content

    mock_get_engine.return_value.__aenter__.return_value = mock_client

    fake_resource = MagicMock()
    fake_resource.id = "my_integration"
    mock_resource.return_value = fake_resource

    result = await integration.upsert_integration({"id": "my_integration"}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == ["my_integration"]
    assert result.total_affected_items == 1
    mock_full_copy.assert_called_once()
    mock_remove.assert_called_once()
    mock_safe_move.assert_not_called()


@pytest.mark.asyncio
@patch("wazuh.integration.Resource.from_dict")
@patch("wazuh.integration.generate_asset_file_path", return_value="/fake/path/integration.json")
@patch("wazuh.integration.exists", side_effect=[True, False, False])
@patch("wazuh.integration.full_copy", side_effect=IOError)
async def test_upsert_integration_backup_fail(mock_full_copy, mock_exists, mock_path, mock_resource):
    """Test failure during backup when updating."""
    fake_resource = MagicMock()
    fake_resource.id = "my_integration"
    mock_resource.return_value = fake_resource

    result = await integration.upsert_integration({"id": "my_integration"}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == []
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.integration.Resource.from_dict")
@patch("wazuh.integration.generate_asset_file_path", return_value="/fake/path/integration.json")
@patch("wazuh.integration.exists", side_effect=[False, True])
@patch("wazuh.integration.save_asset_file")
@patch("wazuh.integration.remove")
@patch("wazuh.integration.get_engine_client")
async def test_upsert_integration_remove_on_create_fail(
    mock_get_engine, mock_remove, mock_save, mock_exists, mock_path, mock_resource
):
    """Test that newly created file is removed if creation fails."""
    fake_resource = MagicMock()
    fake_resource.id = "my_integration"
    mock_resource.return_value = fake_resource

    mock_client = AsyncMock()
    mock_client.catalog.validate_resource.side_effect = WazuhError(9002)
    mock_get_engine.return_value.__aenter__.return_value = mock_client

    result = await integration.upsert_integration({"id": "my_integration"}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == []
    assert result.total_failed_items == 1
    mock_remove.assert_called_once_with("/fake/path/integration.json")


@pytest.mark.asyncio
@patch("wazuh.integration.Resource.from_dict")
@patch("wazuh.integration.generate_asset_file_path", return_value="/fake/path/integration.json")
@patch("wazuh.integration.exists", side_effect=[True, True, True, True])
@patch("wazuh.integration.full_copy")
@patch("wazuh.integration.remove", side_effect=[IOError(), True])
@patch("wazuh.integration.safe_move")
async def test_upsert_integration_delete_previous_fail(
    mock_safe_move,
    mock_remove,
    mock_full_copy,
    mock_exists,
    mock_path,
    mock_resource,
):
    """Test failure removing old file during update triggers backup restore."""
    fake_resource = MagicMock()
    fake_resource.id = "my_integration"
    mock_resource.return_value = fake_resource

    result = await integration.upsert_integration({"id": "my_integration"}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == []
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1
    mock_safe_move.assert_called_once()


@pytest.mark.asyncio
@patch("wazuh.integration.process_array", return_value={"items": [{"id": "my_integration"}], "totalItems": 1})
@patch("wazuh.integration.validate_response_or_raise", new_callable=MagicMock)
@patch("wazuh.integration.get_engine_client")
async def test_get_integration_success(mock_get_engine, mock_validate, mock_process):
    mock_content = AsyncMock()
    mock_content.get_resources.return_value = {"content": [{"id": "my_integration"}]}

    mock_client = AsyncMock()
    mock_client.content = mock_content

    mock_get_engine.return_value.__aenter__.return_value = mock_client
    mock_get_engine.return_value.__aexit__.return_value = AsyncMock()

    result = await integration.get_integration(ids=["my_integration"], policy_type="testing", status=Status.ENABLED)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == [{"id": "my_integration"}]
    assert result.total_affected_items == 1


@pytest.mark.asyncio
@patch("wazuh.integration.get_engine_client")
async def test_get_integration_failure(mock_get_engine):
    mock_content = AsyncMock()
    mock_content.get_resources.return_value = {
        "status": "error",
        "error": "error message",
        "content": [],
    }

    mock_client = AsyncMock()
    mock_client.content = mock_content

    mock_get_engine.return_value.__aenter__.return_value = mock_client

    results = await integration.get_integration(ids=["invalid"], policy_type="testing", status=Status("enabled"))

    assert isinstance(results, AffectedItemsWazuhResult)
    assert results.total_affected_items == 0
    assert results.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.integration.generate_asset_file_path", return_value="/fake/path/integration.json")
@patch("wazuh.integration.exists", return_value=True)
@patch("wazuh.integration.remove")
@patch("wazuh.integration.full_copy")
@patch("wazuh.integration.safe_move")
@patch("wazuh.integration.get_engine_client")
async def test_delete_integration_success(mock_get_engine, mock_safe, mock_copy, mock_remove, mock_exists, mock_path):
    mock_client = AsyncMock()
    mock_client.content.delete_resource.return_value = {"status": "OK"}

    mock_get_engine.return_value.__aenter__.return_value = mock_client

    result = await integration.delete_integration(ids=["my_integration"], policy_type="testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == ["my_integration"]
    assert result.total_affected_items == 1


@pytest.mark.asyncio
@patch("wazuh.integration.full_copy", side_effect=IOError())
@patch("wazuh.integration.generate_asset_file_path", return_value="/fake/path/integration.json")
@patch("wazuh.integration.exists", side_effect=[True, False, False])
async def test_delete_integration_backup_fail(mock_exists, mock_path, mock_full_copy):
    result = await integration.delete_integration(ids=["not_found"], policy_type="testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.integration.safe_move")
@patch("wazuh.integration.remove", side_effect=[IOError(), True])
@patch("wazuh.integration.full_copy")
@patch("wazuh.integration.generate_asset_file_path", return_value="/fake/path/integration.json")
@patch("wazuh.integration.exists", side_effect=[True, True, True])
async def test_delete_integration_delete_fail(mock_exists, mock_path, mock_full_copy, mock_remove, mock_safe_move):
    result = await integration.delete_integration(ids=["not_found"], policy_type="testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    mock_safe_move.assert_called_once()
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.integration.generate_asset_file_path", return_value="/fake/path/integration.json")
@patch("wazuh.integration.exists", side_effect=[False, False])
async def test_delete_integration_not_found(mock_exists, mock_path):
    result = await integration.delete_integration(ids=["not_found"], policy_type="testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1
