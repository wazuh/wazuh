import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from wazuh import WazuhError, decoder
from wazuh.core.engine.models.resources import Status
from wazuh.core.results import AffectedItemsWazuhResult


@pytest.mark.asyncio
@patch("wazuh.decoder.Resource.from_dict")
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", return_value=False)
@patch("wazuh.decoder.save_asset_file")
@patch("wazuh.decoder.get_engine_client")
async def test_upsert_decoder_create_success(mock_get_engine, mock_save, mock_exists, mock_path, mock_resource):
    """Test creating a new decoder successfully."""
    mock_catalog = AsyncMock()
    mock_catalog.validate_resource.return_value = {"status": "OK"}

    mock_content = AsyncMock()
    mock_content.create_resource.return_value = {"status": "OK"}

    mock_client = AsyncMock()
    mock_client.catalog = mock_catalog
    mock_client.content = mock_content

    mock_get_engine.return_value.__aenter__.return_value = mock_client

    fake_resource = MagicMock()
    fake_resource.id = "my_decoder"
    mock_resource.return_value = fake_resource

    result = await decoder.upsert_decoder({"id": "my_decoder"}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == ["my_decoder"]
    assert result.total_affected_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.Resource.from_dict", side_effect=WazuhError(9006))
async def test_upsert_decoder_bad_decoder_format(mock_resource):
    """Test handling bad decoder input."""
    result = await decoder.upsert_decoder({}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == []
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.Resource.from_dict")
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", side_effect=[True, False])
@patch("wazuh.decoder.save_asset_file")
@patch("wazuh.decoder.get_engine_client")
@patch("wazuh.decoder.full_copy")
@patch("wazuh.decoder.remove")
@patch("wazuh.decoder.safe_move")
async def test_upsert_decoder_update_success(
    mock_safe_move,
    mock_remove,
    mock_full_copy,
    mock_get_engine,
    mock_save,
    mock_exists,
    mock_path,
    mock_resource,
):
    """Test updating an existing decoder successfully."""
    mock_catalog = AsyncMock()
    mock_catalog.validate_resource.return_value = {"status": "OK"}

    mock_content = AsyncMock()
    mock_content.update_resource.return_value = {"status": "OK"}

    mock_client = AsyncMock()
    mock_client.catalog = mock_catalog
    mock_client.content = mock_content

    mock_get_engine.return_value.__aenter__.return_value = mock_client

    fake_resource = MagicMock()
    fake_resource.id = "my_decoder"
    mock_resource.return_value = fake_resource

    result = await decoder.upsert_decoder({"id": "my_decoder"}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == ["my_decoder"]
    assert result.total_affected_items == 1
    mock_full_copy.assert_called_once()
    mock_remove.assert_called_once()
    mock_safe_move.assert_not_called()


@pytest.mark.asyncio
@patch("wazuh.decoder.Resource.from_dict")
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", side_effect=[True, False, False])
@patch("wazuh.decoder.full_copy", side_effect=IOError)
async def test_upsert_decoder_backup_fail(mock_full_copy, mock_exists, mock_path, mock_resource):
    """Test failure during backup when updating."""
    fake_resource = MagicMock()
    fake_resource.id = "my_decoder"
    mock_resource.return_value = fake_resource

    result = await decoder.upsert_decoder({"id": "my_decoder"}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == []
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.Resource.from_dict")
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", side_effect=[False, True])
@patch("wazuh.decoder.save_asset_file")
@patch("wazuh.decoder.remove")
@patch("wazuh.decoder.get_engine_client")
async def test_upsert_decoder_remove_on_create_fail(
    mock_get_engine, mock_remove, mock_save, mock_exists, mock_path, mock_resource
):
    """Test that newly created file is removed if creation fails."""
    fake_resource = MagicMock()
    fake_resource.id = "my_decoder"
    mock_resource.return_value = fake_resource

    mock_client = AsyncMock()
    mock_client.catalog.validate_resource.side_effect = WazuhError(9002)
    mock_get_engine.return_value.__aenter__.return_value = mock_client

    result = await decoder.upsert_decoder({"id": "my_decoder"}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == []
    assert result.total_failed_items == 1
    mock_remove.assert_called_once_with("/fake/path/decoder.json")


@pytest.mark.asyncio
@patch("wazuh.decoder.Resource.from_dict")
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", side_effect=[True, True, True, True])
@patch("wazuh.decoder.full_copy")
@patch("wazuh.decoder.remove", side_effect=[IOError(), True])
@patch("wazuh.decoder.safe_move")
async def test_upsert_decoder_delete_previous_fail(
    mock_safe_move,
    mock_remove,
    mock_full_copy,
    mock_exists,
    mock_path,
    mock_resource,
):
    """Test failure removing old file during update triggers backup restore."""
    fake_resource = MagicMock()
    fake_resource.id = "my_decoder"
    mock_resource.return_value = fake_resource

    result = await decoder.upsert_decoder({"id": "my_decoder"}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == []
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1
    mock_safe_move.assert_called_once()


@pytest.mark.asyncio
@patch("wazuh.decoder.process_array", return_value={"items": [{"id": "my_decoder"}], "totalItems": 1})
@patch("wazuh.decoder.validate_response_or_raise", new_callable=MagicMock)
@patch("wazuh.decoder.get_engine_client")
async def test_get_decoder_success(mock_get_engine, mock_validate, mock_process):
    mock_content = AsyncMock()
    mock_content.get_resources.return_value = {"content": [{"id": "my_decoder"}]}

    mock_client = AsyncMock()
    mock_client.content = mock_content

    mock_get_engine.return_value.__aenter__.return_value = mock_client
    mock_get_engine.return_value.__aexit__.return_value = AsyncMock()

    result = await decoder.get_decoder(ids=["my_decoder"], policy_type="testing", status=Status.ENABLED)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == [{"id": "my_decoder"}]
    assert result.total_affected_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.get_engine_client")
async def test_get_decoder_failure(mock_get_engine):
    mock_content = AsyncMock()
    mock_content.get_resources.return_value = {
        "status": "error",
        "error": "error message",
        "content": [],
    }

    mock_client = AsyncMock()
    mock_client.content = mock_content

    mock_get_engine.return_value.__aenter__.return_value = mock_client

    results = await decoder.get_decoder(ids=["invalid"], policy_type="testing", status=Status("enabled"))

    assert isinstance(results, AffectedItemsWazuhResult)
    assert results.total_affected_items == 0
    assert results.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", return_value=True)
@patch("wazuh.decoder.remove")
@patch("wazuh.decoder.full_copy")
@patch("wazuh.decoder.safe_move")
@patch("wazuh.decoder.get_engine_client")
async def test_delete_decoder_success(mock_get_engine, mock_safe, mock_copy, mock_remove, mock_exists, mock_path):
    mock_client = AsyncMock()
    mock_client.content.delete_resource.return_value = {"status": "OK"}

    mock_get_engine.return_value.__aenter__.return_value = mock_client

    result = await decoder.delete_decoder(ids=["my_decoder"], policy_type="testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == ["my_decoder"]
    assert result.total_affected_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.full_copy", side_effect=IOError())
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", side_effect=[True, False, False])
async def test_delete_decoder_backup_fail(mock_exists, mock_path, mock_full_copy):
    result = await decoder.delete_decoder(ids=["not_found"], policy_type="testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.safe_move")
@patch("wazuh.decoder.remove", side_effect=[IOError(), True])
@patch("wazuh.decoder.full_copy")
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", side_effect=[True, True, True])
async def test_delete_decoder_delete_fail(mock_exists, mock_path, mock_full_copy, mock_remove, mock_safe_move):
    result = await decoder.delete_decoder(ids=["not_found"], policy_type="testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    mock_safe_move.assert_called_once()
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", side_effect=[False, False])
async def test_delete_decoder_not_found(mock_exists, mock_path):
    result = await decoder.delete_decoder(ids=["not_found"], policy_type="testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1
