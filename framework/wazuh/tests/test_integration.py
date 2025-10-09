#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import json
from unittest.mock import patch, MagicMock, AsyncMock
from wazuh.core.exception import WazuhError, WazuhInternalError

import pytest

DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", "test_integration")

with patch('wazuh.core.common.getgrnam'):
    with patch('wazuh.core.common.getpwnam'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.integration import create_integration, get_integrations, update_integration, delete_integration
        from wazuh.core.engine.models.integration import Integration
        from wazuh.core.engine.models.policies import PolicyType
        from wazuh.core.engine.models.resources import Status
        from wazuh.core.results import AffectedItemsWazuhResult
        from wazuh.rbac.utils import RESOURCES_CACHE

INTEGRATION_1 = Integration(
    type="integration",
    name="apache_integration",
    id="apache/integration/1",
    description="Apache integration description",
    documentation="# Apache Integration\n\n## Configuration",
    status="enabled",
    kvdbs=["kvdb_a_id", "kvdb_b_id"],
    decoders=["decoder_a_id", "decoder_b_id"]
)

INTEGRATION_2 = Integration(
    type="integration",
    name="cisco_integration",
    id="cisco/integration/1",
    description="Cisco integration description",
    documentation="# Cisco Integration\n\n## Setup",
    status="disabled",
    kvdbs=["kvdb_c_id"],
    decoders=["decoder_c_id"]
)

INTEGRATION_LIST = [INTEGRATION_1, INTEGRATION_2]

MOCK_ENGINE_RESPONSE_SUCCESS = {
    'status': 'OK',
    'content': [
        {
            'type': 'integration',
            'name': 'apache_integration',
            'id': 'apache/integration/1',
            'description': 'Apache integration description',
            'documentation': '# Apache Integration\n\n## Configuration',
            'status': 'enabled',
            'kvdbs': ['kvdb_a_id', 'kvdb_b_id'],
            'decoders': ['decoder_a_id', 'decoder_b_id']
        },
        {
            'type': 'integration',
            'name': 'cisco_integration',
            'id': 'cisco/integration/1',
            'description': 'Cisco integration description',
            'documentation': '# Cisco Integration\n\n## Setup',
            'status': 'disabled',
            'kvdbs': ['kvdb_c_id'],
            'decoders': ['decoder_c_id']
        }
    ]
}

MOCK_ENGINE_RESPONSE_EMPTY = {'status': 'OK', 'content': []}


@pytest.mark.asyncio
@pytest.mark.parametrize("integration, policy_type, expected_filename", [
    (INTEGRATION_1, PolicyType.TESTING, "apache_integration_1.json"),
    (INTEGRATION_2, PolicyType.PRODUCTION, "cisco_integration_1.json"),
])
@patch('wazuh.integration.get_engine_client')
@patch('wazuh.integration.save_asset_file')
@patch('wazuh.integration.generate_asset_filename')
@patch('wazuh.integration.generate_integrations_file_path')
@patch('wazuh.integration.exists', return_value=False)
@patch('wazuh.integration.remove')
async def test_create_integration(mock_remove, mock_exists, mock_generate_path, mock_generate_filename,
                                mock_save_file, mock_get_client, integration,
                                policy_type, expected_filename):
    """Test basic create_integration functionality.

    Parameters
    ----------
    integration : Integration
        The integration object to create.
    policy_type : PolicyType
        The policy type for the integration.
    expected_filename : str
        The expected filename that should be generated.
    """
    mock_generate_filename.return_value = expected_filename
    mock_generate_path.return_value = f"/path/to/{expected_filename}"

    mock_client = MagicMock()
    # Async engine methods
    mock_client.catalog.validate_resource = AsyncMock(return_value={'status': 'OK'})
    mock_client.content.create_resource = AsyncMock(return_value={'status': 'OK'})

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    result = await create_integration(integration, policy_type)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 1
    assert result.affected_items == [expected_filename]
    mock_save_file.assert_called_once()
    mock_client.catalog.validate_resource.assert_called_once()
    mock_client.content.create_resource.assert_called_once()


@pytest.mark.asyncio
@patch('wazuh.integration.get_engine_client')
@patch('wazuh.integration.save_asset_file')
@patch('wazuh.integration.generate_asset_filename', return_value="test.json")
@patch('wazuh.integration.generate_integrations_file_path', return_value="/path/test.json")
@patch('wazuh.integration.exists', return_value=False)
@patch('wazuh.integration.remove')
async def test_create_integration_validation_error(mock_remove, mock_exists, mock_generate_path,
                                                 mock_generate_filename, mock_save_file, mock_get_client):
    """Test create_integration with validation error."""
    mock_client = MagicMock()
    mock_client.catalog.validate_resource = AsyncMock(return_value={'status': 'error', 'error': 'Validation failed'})

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    with patch('wazuh.integration.validate_response_or_raise', side_effect=WazuhError(8002)):
        result = await create_integration(INTEGRATION_1, PolicyType.PRODUCTION)

        assert isinstance(result, AffectedItemsWazuhResult)
        assert result.total_affected_items == 0
        assert len(result.failed_items) == 1


@pytest.mark.asyncio
@patch('wazuh.integration.get_engine_client')
@patch('wazuh.integration.save_asset_file')
@patch('wazuh.integration.generate_asset_filename', return_value="test.json")
@patch('wazuh.integration.generate_integrations_file_path', return_value="/path/test.json")
@patch('wazuh.integration.exists', return_value=False)
@patch('wazuh.integration.remove')
async def test_create_integration_creation_error(mock_remove, mock_exists, mock_generate_path,
                                               mock_generate_filename, mock_save_file, mock_get_client):
    """Test create_integration with creation error."""
    mock_client = MagicMock()
    mock_client.catalog.validate_resource = AsyncMock(return_value={'status': 'OK'})
    mock_client.content.create_resource = AsyncMock(return_value={'status': 'error', 'error': 'Creation failed'})

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    with patch('wazuh.integration.validate_response_or_raise', side_effect=[None, WazuhError(8003)]):
        result = await create_integration(INTEGRATION_1, PolicyType.PRODUCTION)

        assert isinstance(result, AffectedItemsWazuhResult)
        assert result.total_affected_items == 0
        assert len(result.failed_items) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("names, search, status, expected_count", [
    ("apache_integration", None, None, 2),
    ("cisco_integration", None, None, 2),
    ("*", "apache", None, 1),
    ("*", None, Status.ENABLED, 1),
    ("nonexistent", None, None, 0),
])
@patch('wazuh.integration.get_engine_client')
@patch('wazuh.integration.process_array')
async def test_get_integrations(mock_process_array, mock_get_client,
                              names, search, status, expected_count):
    """Test basic get_integrations functionality.

    Parameters
    ----------
    names : str
        Names of integrations to retrieve.
    search : str, optional
        Search string to filter integrations.
    status : Status, optional
        Status to filter integrations.
    expected_count : int
        Expected number of integrations returned.
    """
    mock_client = MagicMock()
    mock_client.content.get_multiple_resources = AsyncMock(return_value=MOCK_ENGINE_RESPONSE_SUCCESS)

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    mock_process_array.return_value = {
        'items': MOCK_ENGINE_RESPONSE_SUCCESS['content'][:expected_count],
        'totalItems': expected_count
    }

    result = await get_integrations(PolicyType.PRODUCTION, names=[names], search=search, status=status)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == expected_count
    mock_client.content.get_multiple_resources.assert_called_once()


@pytest.mark.asyncio
@patch('wazuh.integration.get_engine_client')
async def test_get_integrations_engine_error(mock_get_client):
    """Test get_integrations with engine error."""
    mock_client = MagicMock()
    mock_client.content.get_multiple_resources = AsyncMock(return_value={'status': 'error', 'error': 'Engine error'})

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    with patch('wazuh.integration.validate_response_or_raise', side_effect=WazuhError(8007)):
        with pytest.raises(WazuhError) as exc_info:
            await get_integrations(PolicyType.PRODUCTION, names=["test"], search=None, status=None)
        assert exc_info.value.code == 8007


@pytest.mark.asyncio
@patch('wazuh.integration.get_engine_client')
@patch('wazuh.integration.process_array')
async def test_get_integrations_empty_result(mock_process_array, mock_get_client):
    """Test get_integrations with empty result."""
    mock_client = MagicMock()
    mock_client.content.get_multiple_resources = AsyncMock(return_value=MOCK_ENGINE_RESPONSE_EMPTY)

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    mock_process_array.return_value = {'items': [], 'totalItems': 0}

    result = await get_integrations(PolicyType.PRODUCTION, names=["nonexistent"], search=None, status=None)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 0
    assert result.affected_items == []


# Tests for update_integration
@pytest.mark.asyncio
@pytest.mark.parametrize("integration, policy_type", [
    (INTEGRATION_1, PolicyType.PRODUCTION),
    (INTEGRATION_2, PolicyType.PRODUCTION),
])
@patch('wazuh.integration.get_engine_client')
@patch('wazuh.integration.save_asset_file')
@patch('wazuh.integration.generate_asset_filename')
@patch('wazuh.integration.generate_integrations_file_path')
@patch('wazuh.integration.exists', return_value=True)
@patch('wazuh.integration.remove')
@patch('wazuh.integration.full_copy')
@patch('wazuh.integration.safe_move')
async def test_update_integration(mock_safe_move, mock_full_copy, mock_remove, mock_exists,
                                mock_generate_path, mock_generate_filename, mock_save_file,
                                mock_get_client, integration, policy_type):
    """Test basic update_integration functionality.

    Parameters
    ----------
    integration : Integration
        The integration object to update.
    policy_type : PolicyType
        The policy type for the integration.
    """
    filename = f"{integration.name}.json"
    file_path = f"/path/to/{filename}"

    mock_generate_filename.return_value = filename
    mock_generate_path.return_value = file_path

    mock_client = MagicMock()
    mock_client.catalog.validate_resource = AsyncMock(return_value={'status': 'OK'})
    mock_client.content.update_resource = AsyncMock(return_value={'status': 'OK'})

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    result = await update_integration(integration, policy_type)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 1
    assert result.affected_items == [filename]
    mock_full_copy.assert_called_once_with(file_path, f"{file_path}.backup")
    mock_save_file.assert_called_once()
    mock_client.catalog.validate_resource.assert_called_once()
    mock_client.content.update_resource.assert_called_once()

    # Adjust remove assertions: one for original file, one for backup cleanup
    remove_calls = [call_args.args[0] for call_args in mock_remove.call_args_list]
    assert file_path in remove_calls  # original removal
    assert f"{file_path}.backup" in remove_calls  # backup cleanup


@pytest.mark.asyncio
@patch('wazuh.integration.generate_asset_filename', return_value="test.json")
@patch('wazuh.integration.generate_integrations_file_path', return_value="/path/test.json")
@patch('wazuh.integration.exists', return_value=False)
async def test_update_integration_file_not_exists(mock_exists, mock_generate_path, mock_generate_filename):
    """Test update_integration when file doesn't exist."""
    result = await update_integration(INTEGRATION_1, PolicyType.PRODUCTION)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 0
    assert len(result.failed_items) == 1


@pytest.mark.asyncio
@patch('wazuh.integration.get_engine_client')
@patch('wazuh.integration.save_asset_file')
@patch('wazuh.integration.generate_asset_filename', return_value="test.json")
@patch('wazuh.integration.generate_integrations_file_path', return_value="/path/test.json")
@patch('wazuh.integration.exists', return_value=True)
@patch('wazuh.integration.remove')
@patch('wazuh.integration.full_copy', side_effect=IOError("Backup failed"))
@patch('wazuh.integration.safe_move')
async def test_update_integration_backup_error(mock_safe_move, mock_full_copy, mock_remove, mock_exists,
                                             mock_generate_path, mock_generate_filename, mock_save_file,
                                             mock_get_client):
    """Test update_integration with backup error."""
    # Mock the engine client
    mock_client = MagicMock()
    mock_client.catalog.validate_resource = AsyncMock(return_value={'status': 'OK'})
    mock_client.content.update_resource = AsyncMock(return_value={'status': 'OK'})

    # Mock the async context manager
    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    result = await update_integration(INTEGRATION_1, PolicyType.PRODUCTION)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 0
    assert len(result.failed_items) == 1


@pytest.mark.asyncio
@patch('wazuh.integration.get_engine_client')
@patch('wazuh.integration.save_asset_file')
@patch('wazuh.integration.generate_asset_filename', return_value="test.json")
@patch('wazuh.integration.generate_integrations_file_path', return_value="/path/test.json")
@patch('wazuh.integration.exists', return_value=True)
@patch('wazuh.integration.remove', side_effect=IOError("Remove failed"))
@patch('wazuh.integration.full_copy')
@patch('wazuh.integration.safe_move')
async def test_update_integration_remove_error(mock_safe_move, mock_full_copy, mock_remove, mock_exists,
                                             mock_generate_path, mock_generate_filename, mock_save_file,
                                             mock_get_client):
    """Test update_integration with remove error."""
    # Mock the engine client
    mock_client = MagicMock()
    mock_client.catalog.validate_resource = AsyncMock(return_value={'status': 'OK'})
    mock_client.content.update_resource = AsyncMock(return_value={'status': 'OK'})

    # Mock the async context manager
    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    result = await update_integration(INTEGRATION_1, PolicyType.PRODUCTION)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 0
    assert len(result.failed_items) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("names, expected_success_count", [
    (["apache_integration"], 1),
    (["apache_integration", "cisco_integration"], 2),
])
@patch('wazuh.integration.get_engine_client')
@patch('wazuh.integration.generate_integrations_file_path')
@patch('wazuh.integration.exists', return_value=True)
@patch('wazuh.integration.full_copy')
@patch('wazuh.integration.remove')
@patch('wazuh.integration.safe_move')
async def test_delete_integration(mock_safe_move, mock_remove, mock_full_copy, mock_exists,
                                mock_generate_path, mock_get_client,
                                names, expected_success_count):
    """Test basic delete_integration functionality.

    Parameters
    ----------
    names : List[str]
        List of integration names to delete.
    expected_success_count : int
        Expected number of successful deletions.
    """
    mock_generate_path.side_effect = [f"/path/to/{name}.json" for name in names]

    mock_client = MagicMock()
    mock_client.content.delete_resource = AsyncMock(return_value={'status': 'OK'})

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    result = await delete_integration(names, PolicyType.PRODUCTION)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == expected_success_count
    assert len(result.affected_items) == expected_success_count
    assert mock_full_copy.call_count == expected_success_count
    assert mock_remove.call_count == expected_success_count * 2
    mock_client.content.delete_resource.assert_called()


@pytest.mark.asyncio
@patch('wazuh.integration.generate_integrations_file_path', return_value="/path/nonexistent.json")
@patch('wazuh.integration.exists', return_value=False)
async def test_delete_integration_file_not_exists(mock_exists, mock_generate_path):
    """Test delete_integration when file doesn't exist."""
    result = await delete_integration(["nonexistent"], PolicyType.PRODUCTION)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 0
    assert len(result.failed_items) == 1


@pytest.mark.asyncio
@patch('wazuh.integration.get_engine_client')
@patch('wazuh.integration.generate_integrations_file_path', return_value="/path/test.json")
@patch('wazuh.integration.exists', return_value=True)
@patch('wazuh.integration.full_copy', side_effect=IOError("Backup failed"))
@patch('wazuh.integration.safe_move')
async def test_delete_integration_backup_error(mock_safe_move, mock_full_copy, mock_exists,
                                             mock_generate_path, mock_get_client):
    """Test delete_integration with backup error."""
    # Mock the engine client
    mock_client = MagicMock()
    mock_client.content.delete_resource = AsyncMock(return_value={'status': 'OK'})

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    result = await delete_integration(["test"], PolicyType.PRODUCTION)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 0
    assert len(result.failed_items) == 1


@pytest.mark.asyncio
@patch('wazuh.integration.get_engine_client')
@patch('wazuh.integration.generate_integrations_file_path', return_value="/path/test.json")
@patch('wazuh.integration.exists', return_value=True)
@patch('wazuh.integration.full_copy')
@patch('wazuh.integration.remove', side_effect=IOError("Remove failed"))
@patch('wazuh.integration.safe_move')
async def test_delete_integration_remove_error(mock_safe_move, mock_remove, mock_full_copy, mock_exists,
                                             mock_generate_path, mock_get_client):
    """Test delete_integration with remove error."""
    mock_client = MagicMock()
    mock_client.content.delete_resource = AsyncMock(return_value={'status': 'OK'})

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    result = await delete_integration(["test"], PolicyType.PRODUCTION)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 0
    assert len(result.failed_items) == 1


@pytest.mark.asyncio
@patch('wazuh.integration.get_engine_client')
@patch('wazuh.integration.generate_integrations_file_path', return_value="/path/test.json")
@patch('wazuh.integration.exists', return_value=True)
@patch('wazuh.integration.full_copy')
@patch('wazuh.integration.remove')
@patch('wazuh.integration.safe_move')
async def test_delete_integration_engine_error(mock_safe_move, mock_remove, mock_full_copy, mock_exists,
                                             mock_generate_path, mock_get_client):
    """Test delete_integration with engine error."""
    mock_client = MagicMock()
    mock_client.content.delete_resource = AsyncMock(return_value={'status': 'error', 'error': 'Delete failed'})

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    with patch('wazuh.integration.validate_response_or_raise', side_effect=WazuhError(8007)):
        result = await delete_integration(["test"], PolicyType.PRODUCTION)

        assert isinstance(result, AffectedItemsWazuhResult)
        assert result.total_affected_items == 0
        assert len(result.failed_items) == 1


# Tests for mixed scenarios
@pytest.mark.asyncio
@patch('wazuh.integration.generate_integrations_file_path')
@patch('wazuh.integration.exists')
async def test_delete_integration_mixed_results(mock_exists, mock_generate_path):
    """Test delete_integration with mixed success/failure results."""
    names = ["existing", "nonexistent"]
    mock_generate_path.side_effect = [f"/path/{name}.json" for name in names]
    mock_exists.side_effect = [True, False, False, False]

    with patch('wazuh.integration.get_engine_client') as mock_get_client:
        mock_client = MagicMock()
        mock_client.content.delete_resource = AsyncMock(return_value={'status': 'OK'})

        mock_context_manager = AsyncMock()
        mock_context_manager.__aenter__.return_value = mock_client
        mock_context_manager.__aexit__.return_value = None
        mock_get_client.return_value = mock_context_manager

        with patch('wazuh.integration.full_copy'), \
             patch('wazuh.integration.remove'), \
             patch('wazuh.integration.safe_move'):

            result = await delete_integration(names, PolicyType.PRODUCTION)

            assert isinstance(result, AffectedItemsWazuhResult)
            assert result.total_affected_items == 1
            assert len(result.failed_items) == 1
            assert result.affected_items == ["existing"]


@pytest.mark.asyncio
@patch('wazuh.integration.get_engine_client')
@patch('wazuh.integration.process_array')
async def test_get_integrations_with_filters(mock_process_array, mock_get_client):
    """Test get_integrations with various filter combinations."""
    mock_client = MagicMock()
    mock_client.content.get_multiple_resources = AsyncMock(return_value=MOCK_ENGINE_RESPONSE_SUCCESS)

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    mock_process_array.return_value = {
        'items': [MOCK_ENGINE_RESPONSE_SUCCESS['content'][0]],  # Only enabled integration
        'totalItems': 1
    }

    result = await get_integrations(PolicyType.PRODUCTION, names=["*"], search=None, status=Status.ENABLED)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 1

    mock_process_array.assert_called_with(
        MOCK_ENGINE_RESPONSE_SUCCESS['content'],
        search_text=None,
        filters={'status': Status.ENABLED}
    )


@pytest.mark.asyncio
@patch('wazuh.integration.get_engine_client')
@patch('wazuh.integration.process_array')
async def test_get_integrations_with_search(mock_process_array, mock_get_client):
    """Test get_integrations with search functionality."""
    mock_client = MagicMock()
    mock_client.content.get_multiple_resources = AsyncMock(return_value=MOCK_ENGINE_RESPONSE_SUCCESS)

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    mock_process_array.return_value = {
        'items': [MOCK_ENGINE_RESPONSE_SUCCESS['content'][0]],  # Only apache integration
        'totalItems': 1
    }

    result = await get_integrations(PolicyType.PRODUCTION, names=["*"], search="apache", status=None)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 1

    mock_process_array.assert_called_with(
        MOCK_ENGINE_RESPONSE_SUCCESS['content'],
        search_text="apache",
        filters=None
    )
