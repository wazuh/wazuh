#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import patch, MagicMock, AsyncMock
from wazuh.core.exception import WazuhError

import pytest

DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", "test_integrations_order")


def failed_error_codes(result):
    return {err.code for err in result.failed_items.keys()}


with patch("wazuh.core.common.getgrnam"):
    with patch("wazuh.core.common.getpwnam"):
        sys.modules["wazuh.rbac.orm"] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules["wazuh.rbac.orm"]
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.integrations_order import (
            upsert_integrations_order,
            get_integrations_order,
            delete_integrations_order,
        )
        from wazuh.core.engine.models.integrations_order import IntegrationsOrder, IntegrationInfo
        from wazuh.core.engine.models.policies import PolicyType
        from wazuh.core.results import AffectedItemsWazuhResult

INTEGRATION_INFO_1 = IntegrationInfo(id="apache", name="Apache Integration")
INTEGRRATION_INFO_2 = IntegrationInfo(id="cisco", name="Cisco Integration")
INTEGRATION_INFO_3 = IntegrationInfo(id="nginx", name="Nginx Integration")

INTEGRATIONS_ORDER_1 = IntegrationsOrder(order=[INTEGRATION_INFO_1, INTEGRRATION_INFO_2])
INTEGRATIONS_ORDER_2 = IntegrationsOrder(order=[INTEGRRATION_INFO_2, INTEGRATION_INFO_3, INTEGRATION_INFO_1])
INTEGRATIONS_ORDER_EMPTY = IntegrationsOrder(order=[])

MOCK_ENGINE_RESPONSE_SUCCESS = {
    "status": "OK",
    "content": [{"id": "apache", "name": "Apache Integration"}, {"id": "cisco", "name": "Cisco Integration"}],
}

MOCK_ENGINE_RESPONSE_SUCCESS_2 = {
    "status": "OK",
    "content": [
        {"id": "cisco", "name": "Cisco Integration"},
        {"id": "nginx", "name": "Nginx Integration"},
        {"id": "apache", "name": "Apache Integration"},
    ],
}

MOCK_ENGINE_RESPONSE_EMPTY = {"status": "OK", "content": []}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "integrations_order, policy_type",
    [
        (INTEGRATIONS_ORDER_1, PolicyType.TESTING),
        (INTEGRATIONS_ORDER_2, PolicyType.PRODUCTION),
        (INTEGRATIONS_ORDER_EMPTY, PolicyType.TESTING),
    ],
)
@patch("wazuh.integrations_order.get_engine_client")
@patch("wazuh.integrations_order.save_asset_file")
@patch("wazuh.integrations_order.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.integrations_order.exists", return_value=False)
@patch("wazuh.integrations_order.remove")
async def test_upsert_integrations_order(
    mock_remove, mock_exists, mock_generate_path, mock_save_file, mock_get_client, integrations_order, policy_type
):
    """Test basic upsert_integrations_order functionality.

    Parameters
    ----------
    integrations_order : IntegrationsOrder
        The integrations order object to create.
    policy_type : PolicyType
        The policy type for the integrations order.
    """
    expected_filename = "integrations_order"
    mock_generate_path.return_value = f"/path/to/{expected_filename}"

    mock_client = MagicMock()
    mock_client.integrations_order = MagicMock()
    mock_client.integrations_order.create_order = AsyncMock(return_value={"status": "OK"})

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    result = await upsert_integrations_order(integrations_order, policy_type)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 1
    assert result.affected_items == [expected_filename]
    mock_save_file.assert_called_once()
    mock_client.integrations_order.create_order.assert_called_once()


@pytest.mark.asyncio
@patch("wazuh.integrations_order.get_engine_client")
@patch("wazuh.integrations_order.save_asset_file")
@patch("wazuh.integrations_order.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.integrations_order.exists", return_value=False)
@patch("wazuh.integrations_order.remove")
async def test_upsert_integrations_order_engine_error(
    mock_remove, mock_exists, mock_generate_path, mock_save_file, mock_get_client
):
    """Test upsert_integrations_order with engine error."""
    mock_client = MagicMock()
    mock_client.integrations_order = MagicMock()
    mock_client.integrations_order.create_order = AsyncMock(return_value={"status": "error", "error": "Engine error"})

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    with patch("wazuh.integrations_order.validate_response_or_raise", side_effect=WazuhError(9012)):
        result = await upsert_integrations_order(INTEGRATIONS_ORDER_1, PolicyType.PRODUCTION)
        assert isinstance(result, AffectedItemsWazuhResult)
        assert result.total_affected_items == 0
        assert len(result.failed_items) == 1
        assert 9012 in failed_error_codes(result)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "policy_type, mock_response, expected_count",
    [
        (PolicyType.TESTING, MOCK_ENGINE_RESPONSE_SUCCESS, 1),
        (PolicyType.PRODUCTION, MOCK_ENGINE_RESPONSE_SUCCESS_2, 1),
        (PolicyType.TESTING, MOCK_ENGINE_RESPONSE_EMPTY, 1),
    ],
)
@patch("wazuh.integrations_order.get_engine_client")
async def test_get_integrations_order(mock_get_client, policy_type, mock_response, expected_count):
    """Test basic get_integrations_order functionality.

    Parameters
    ----------
    policy_type : PolicyType
        The policy type for the integrations order.
    mock_response : dict
        Mock response from the engine.
    expected_count : int
        Expected number of integrations returned.
    """
    mock_client = MagicMock()
    mock_client.integrations_order = MagicMock()
    mock_client.integrations_order.get_order = AsyncMock(return_value=mock_response)

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    result = await get_integrations_order(policy_type)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == expected_count
    assert len(result.affected_items) == expected_count
    if expected_count > 0:
        assert result.affected_items == [mock_response["content"]]
    mock_client.integrations_order.get_order.assert_called_once_with(policy_type=policy_type)


@pytest.mark.asyncio
@patch("wazuh.integrations_order.get_engine_client")
async def test_get_integrations_order_engine_error(mock_get_client):
    """Test get_integrations_order with engine error."""
    mock_client = MagicMock()
    mock_client.integrations_order = MagicMock()
    mock_client.integrations_order.get_order = AsyncMock(return_value={"status": "error", "error": "Engine error"})

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    with patch("wazuh.integrations_order.validate_response_or_raise", side_effect=WazuhError(8011)):
        with pytest.raises(WazuhError) as exc_info:
            await get_integrations_order(PolicyType.PRODUCTION)
        assert exc_info.value.code == 8011


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "policy_type",
    [
        PolicyType.TESTING,
        PolicyType.PRODUCTION,
    ],
)
@patch("wazuh.integrations_order.get_engine_client")
@patch("wazuh.integrations_order.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.integrations_order.exists", return_value=True)
@patch("wazuh.integrations_order.full_copy")
@patch("wazuh.integrations_order.remove")
@patch("wazuh.integrations_order.safe_move")
async def test_delete_integrations_order(
    mock_safe_move, mock_remove, mock_full_copy, mock_exists, mock_generate_path, mock_get_client, policy_type
):
    """Test basic delete_integrations_order functionality.

    Parameters
    ----------
    policy_type : PolicyType
        The policy type for the integrations order.
    """
    expected_filename = "integrations_order"
    file_path = f"/path/to/{expected_filename}"

    mock_generate_path.return_value = file_path

    mock_client = MagicMock()
    mock_client.integrations_order = MagicMock()
    mock_client.integrations_order.delete_order = AsyncMock(return_value={"status": "OK"})

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    result = await delete_integrations_order(policy_type)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 1
    assert result.affected_items == [expected_filename]
    mock_full_copy.assert_called_once_with(file_path, f"{file_path}.bak")
    # remove called for original file and bak file cleanup
    assert mock_remove.call_count == 2
    assert mock_remove.call_args_list[0].args[0] == file_path
    assert mock_remove.call_args_list[1].args[0] == f"{file_path}.bak"
    mock_client.integrations_order.delete_order.assert_called_once()


@pytest.mark.asyncio
@patch("wazuh.integrations_order.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.integrations_order.exists", return_value=False)
async def test_delete_integrations_order_file_not_exists(mock_exists, mock_generate_path):
    """Test delete_integrations_order when file doesn't exist."""
    result = await delete_integrations_order(PolicyType.PRODUCTION)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 0
    assert len(result.failed_items) == 1
    assert 9006 in failed_error_codes(result)


@pytest.mark.asyncio
@patch("wazuh.integrations_order.get_engine_client")
@patch("wazuh.integrations_order.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.integrations_order.exists", return_value=True)
@patch("wazuh.integrations_order.full_copy", side_effect=IOError("bak failed"))
@patch("wazuh.integrations_order.safe_move")
async def test_delete_integrations_order_bak_error(
    mock_safe_move, mock_full_copy, mock_exists, mock_generate_path, mock_get_client
):
    """Test delete_integrations_order with bak error."""
    mock_client = MagicMock()
    mock_client.integrations_order = MagicMock()

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    result = await delete_integrations_order(PolicyType.PRODUCTION)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 0
    assert len(result.failed_items) == 1
    assert 1019 in failed_error_codes(result)


@pytest.mark.asyncio
@patch("wazuh.integrations_order.get_engine_client")
@patch("wazuh.integrations_order.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.integrations_order.exists", return_value=True)
@patch("wazuh.integrations_order.full_copy")
@patch("wazuh.integrations_order.remove", side_effect=IOError("Remove failed"))
@patch("wazuh.integrations_order.safe_move")
async def test_delete_integrations_order_remove_error(
    mock_safe_move, mock_remove, mock_full_copy, mock_exists, mock_generate_path, mock_get_client
):
    """Test delete_integrations_order with remove error."""
    mock_client = MagicMock()
    mock_client.integrations_order = MagicMock()

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    result = await delete_integrations_order(PolicyType.PRODUCTION)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 0
    assert len(result.failed_items) == 1
    assert 1907 in failed_error_codes(result)


@pytest.mark.asyncio
@patch("wazuh.integrations_order.get_engine_client")
@patch("wazuh.integrations_order.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.integrations_order.exists", return_value=True)
@patch("wazuh.integrations_order.full_copy")
@patch("wazuh.integrations_order.remove")
@patch("wazuh.integrations_order.safe_move")
async def test_delete_integrations_order_engine_error(
    mock_safe_move, mock_remove, mock_full_copy, mock_exists, mock_generate_path, mock_get_client
):
    """Test delete_integrations_order with engine error."""
    mock_client = MagicMock()
    mock_client.integrations_order = MagicMock()
    mock_client.integrations_order.delete_order = AsyncMock(return_value={"status": "error", "error": "Delete failed"})

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    with patch("wazuh.integrations_order.validate_response_or_raise", side_effect=WazuhError(9013)):
        result = await delete_integrations_order(PolicyType.PRODUCTION)
        assert isinstance(result, AffectedItemsWazuhResult)
        assert result.total_affected_items == 0
        assert len(result.failed_items) == 1
        assert 9013 in failed_error_codes(result)


@pytest.mark.asyncio
@patch("wazuh.integrations_order.get_engine_client")
@patch("wazuh.integrations_order.save_asset_file")
@patch("wazuh.integrations_order.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.integrations_order.exists", return_value=False)
@patch("wazuh.integrations_order.remove")
async def test_upsert_integrations_order_with_empty_order(
    mock_remove, mock_exists, mock_generate_path, mock_save_file, mock_get_client
):
    """Test upsert_integrations_order with empty integrations list."""
    mock_client = MagicMock()
    mock_client.integrations_order = MagicMock()
    mock_client.integrations_order.create_order = AsyncMock(return_value={"status": "OK"})

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    result = await upsert_integrations_order(INTEGRATIONS_ORDER_EMPTY, PolicyType.TESTING)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 1
    assert result.affected_items == ["integrations_order"]


@pytest.mark.asyncio
@patch("wazuh.integrations_order.get_engine_client")
async def test_get_integrations_order_empty_response(mock_get_client):
    """Test get_integrations_order with empty response from engine."""
    mock_client = MagicMock()
    mock_client.integrations_order = MagicMock()
    mock_client.integrations_order.get_order = AsyncMock(return_value=MOCK_ENGINE_RESPONSE_EMPTY)

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_client
    mock_context_manager.__aexit__.return_value = None
    mock_get_client.return_value = mock_context_manager

    result = await get_integrations_order(PolicyType.TESTING)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 1
    assert result.affected_items == [[]]


@pytest.mark.asyncio
@patch("wazuh.integrations_order.get_engine_client")
@patch("wazuh.integrations_order.save_asset_file", side_effect=IOError("Save failed"))
@patch("wazuh.integrations_order.generate_asset_file_path", return_value="/fake/path/decoder.json")
@patch("wazuh.integrations_order.exists", return_value=False)
@patch("wazuh.integrations_order.remove")
async def test_upsert_integrations_order_save_file_error(
    mock_remove, mock_exists, mock_generate_path, mock_save_file, mock_get_client
):
    """Test upsert_integrations_order with file save error."""
    with pytest.raises(IOError) as exc_info:
        await upsert_integrations_order(INTEGRATIONS_ORDER_1, PolicyType.PRODUCTION)
    assert str(exc_info.value) == "Save failed"
