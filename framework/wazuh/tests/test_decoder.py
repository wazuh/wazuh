import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from wazuh import WazuhError, decoder
from wazuh.core.engine.models.resources import ResourceError, Status
from wazuh.core.results import AffectedItemsWazuhResult


@pytest.mark.asyncio
@patch("wazuh.decoder.resource_from_dict")
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", return_value=False)
@patch("wazuh.decoder.save_asset_file")
@patch("wazuh.decoder.get_engine_client")
async def test_create_decoder_success(
    mock_get_engine, mock_save, mock_exists, mock_path, mock_resource
):
    mock_catalog = AsyncMock()
    mock_catalog.validate_resource.return_value = {"status": "OK"}

    mock_content = AsyncMock()
    mock_content.create_resource.return_value = {"status": "OK"}

    mock_client = AsyncMock()
    mock_client.catalog = mock_catalog
    mock_client.content = mock_content

    mock_get_engine.return_value.__aenter__.return_value = mock_client
    mock_get_engine.return_value.__aexit__.return_value = AsyncMock()

    fake_resource = MagicMock()
    fake_resource.name = "my_decoder"
    fake_resource.__getitem__.return_value = "my_decoder"
    mock_resource.return_value = fake_resource

    result = await decoder.create_decoder({"name": "my_decoder"}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == ["my_decoder"]
    assert result.total_affected_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.resource_from_dict", side_effect=ResourceError())
async def test_create_decoder_bad_decoder_format(mock_resource):
    result = await decoder.create_decoder({}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == []
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.get_engine_client")
@patch("wazuh.decoder.save_asset_file")
@patch("wazuh.decoder.exists", return_value=False)
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.resource_from_dict")
@patch("wazuh.decoder.validate_response_or_raise", side_effect=WazuhError(9002))
async def test_create_decoder_validation_fail(
    mock_validate, mock_resource, mock_path, mock_exists, mock_save, mock_get_engine
):
    fake_resource = MagicMock()
    fake_resource.name = "my_decoder"
    fake_resource.__getitem__.side_effect = lambda key: "my_decoder"
    mock_resource.return_value = fake_resource

    mock_client = AsyncMock()
    mock_client.catalog.validate_resource.return_value = {
        "status": "error",
        "error": "some error",
    }
    mock_client.content.create_resource.return_value = {"status": "success"}

    mock_get_engine.return_value.__aenter__.return_value = mock_client
    mock_get_engine.return_value.__aexit__.return_value = False

    result = await decoder.create_decoder({"name": "my_decoder"}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == []
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.resource_from_dict")
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", side_effect=[True, False])
@patch("wazuh.decoder.save_asset_file")
@patch("wazuh.decoder.get_engine_client")
async def test_create_decoder_already_exists(
    mock_get_engine, mock_save, mock_exists, mock_path, mock_resource
):
    mock_client = AsyncMock()
    mock_get_engine.return_value.__aenter__.return_value = mock_client
    mock_get_engine.return_value.__aexit__.return_value = AsyncMock()

    fake_resource = MagicMock()
    fake_resource.name = "my_decoder"
    fake_resource.__getitem__.return_value = "my_decoder"
    mock_resource.return_value = fake_resource

    result = await decoder.create_decoder({"name": "my_decoder"}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == []
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.process_array", return_value={"items": [{"name": "my_decoder"}], "totalItems": 1})
@patch("wazuh.decoder.validate_response_or_raise", new_callable=MagicMock)
@patch("wazuh.decoder.get_engine_client")
async def test_get_decoder_success(mock_get_engine, mock_validate, mock_process):
    mock_content = AsyncMock()
    mock_content.get_resources.return_value = {"content": [{"name": "my_decoder"}]}

    mock_client = AsyncMock()
    mock_client.content = mock_content

    mock_get_engine.return_value.__aenter__.return_value = mock_client
    mock_get_engine.return_value.__aexit__.return_value = AsyncMock()

    result = await decoder.get_decoder(
        names=["my_decoder"], policy_type="testing", status=Status.ENABLED
    )

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == [{"name": "my_decoder"}]
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

    results = await decoder.get_decoder(
        names=["invalid"], policy_type="testing", status=Status("enabled")
    )

    assert isinstance(results, AffectedItemsWazuhResult)
    assert results.total_affected_items == 0
    assert results.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.resource_from_dict")
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", return_value=True)
@patch("wazuh.decoder.save_asset_file")
@patch("wazuh.decoder.remove")
@patch("wazuh.decoder.full_copy")
@patch("wazuh.decoder.safe_move")
@patch("wazuh.decoder.get_engine_client")
async def test_update_decoder_success(
    mock_get_engine,
    mock_safe,
    mock_copy,
    mock_remove,
    mock_save,
    mock_exists,
    mock_path,
    mock_resource,
):
    mock_resource.return_value = {"name": "my_decoder"}

    mock_client = AsyncMock()
    mock_client.catalog.validate_resource.return_value = {"status": "OK"}
    mock_client.content.update_resource.return_value = {"status": "OK"}

    mock_get_engine.return_value.__aenter__.return_value = mock_client

    result = await decoder.update_decoder({"name": "my_decoder"}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == ["my_decoder"]
    assert result.total_affected_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.resource_from_dict", side_effect=ResourceError())
async def test_update_decoder_bad_decoder(mock_resource):
    result = await decoder.update_decoder({}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == []
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.resource_from_dict")
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", side_effect=[False, False])
async def test_update_decoder_not_found(mock_exists, mock_path, mock_resource):
    mock_resource.return_value = {"name": "missing"}

    result = await decoder.update_decoder({"name": "missing"}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.full_copy", side_effect=IOError())
@patch("wazuh.decoder.resource_from_dict")
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", side_effect=[True, False])
async def test_update_decoder_backup_fail(
    mock_exists, mock_path, mock_resource, mock_full_copy
):
    mock_resource.return_value = {"name": "my_decoder"}

    result = await decoder.update_decoder({"name": "my_decoder"}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == []
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.safe_move")
@patch("wazuh.decoder.remove", side_effect=IOError())
@patch("wazuh.decoder.full_copy")
@patch("wazuh.decoder.resource_from_dict")
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", side_effect=[True, True])
async def test_update_decoder_delete_previous_fail(
    mock_exists, mock_path, mock_resource, mock_full_copy, mock_remove, mock_safe_move
):
    mock_resource.return_value = {"name": "my_decoder"}

    result = await decoder.update_decoder({"name": "my_decoder"}, "testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    mock_safe_move.assert_called_once()
    assert result.affected_items == []
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", return_value=True)
@patch("wazuh.decoder.remove")
@patch("wazuh.decoder.full_copy")
@patch("wazuh.decoder.safe_move")
@patch("wazuh.decoder.get_engine_client")
async def test_delete_decoder_success(
    mock_get_engine, mock_safe, mock_copy, mock_remove, mock_exists, mock_path
):
    mock_client = AsyncMock()
    mock_client.content.delete_resource.return_value = {"status": "OK"}

    mock_get_engine.return_value.__aenter__.return_value = mock_client

    result = await decoder.delete_decoder(names=["my_decoder"], policy_type="testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == ["my_decoder"]
    assert result.total_affected_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.full_copy", side_effect=IOError())
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", side_effect=[True, False])
async def test_delete_decoder_backup_fail(mock_exists, mock_path, mock_full_copy):
    result = await decoder.delete_decoder(names=["not_found"], policy_type="testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.safe_move")
@patch("wazuh.decoder.remove", side_effect=IOError())
@patch("wazuh.decoder.full_copy")
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", side_effect=[True, True])
async def test_delete_decoder_delete_fail(
    mock_exists, mock_path, mock_full_copy, mock_remove, mock_safe_move
):
    result = await decoder.delete_decoder(names=["not_found"], policy_type="testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    mock_safe_move.assert_called_once()
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch("wazuh.decoder.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.decoder.exists", side_effect=[False, False])
async def test_delete_decoder_not_found(mock_exists, mock_path):
    result = await decoder.delete_decoder(names=["not_found"], policy_type="testing")

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 0
    assert result.total_failed_items == 1
