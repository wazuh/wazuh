# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.analysisd import *



@pytest.mark.asyncio
@patch('wazuh.analysisd.node_type', 'master')
@patch('wazuh.analysisd.send_reload_ruleset_msg')
async def test_reload_ruleset_master_ok(mock_send_reload_ruleset_msg):
    """Test reload_ruleset() works as expected for master node with successful reload."""
    mock_response = MagicMock()
    mock_response.is_ok.return_value = True
    mock_response.has_warnings.return_value = False
    mock_send_reload_ruleset_msg.return_value = mock_response

    result = await reload_ruleset()
    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 1
    assert result.failed_items == {}


@pytest.mark.asyncio
@patch('wazuh.analysisd.node_type', 'master')
@patch('wazuh.analysisd.send_reload_ruleset_msg')
async def test_reload_ruleset_master_nok(mock_send_reload_ruleset_msg):
    """Test reload_ruleset() for master node with error in reload."""
    mock_response = MagicMock()
    mock_response.is_ok.return_value = False
    mock_response.errors = ['error1']
    mock_send_reload_ruleset_msg.return_value = mock_response

    result = await reload_ruleset()
    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch('wazuh.analysisd.node_type', 'worker')
@patch('wazuh.analysisd.local_client.LocalClient')
@patch('wazuh.analysisd.set_reload_ruleset_flag')
async def test_reload_ruleset_worker_ok(mock_set_reload_flag, mock_local_client):
    """Test reload_ruleset() works as expected for worker node with successful reload."""
    mock_set_reload_flag.return_value = 'Reload ruleset flag set successfully'
    result = await reload_ruleset()
    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == 1
    assert result.failed_items == {}


@pytest.mark.asyncio
@patch('wazuh.analysisd.node_type', 'worker')
@patch('wazuh.analysisd.local_client.LocalClient')
@patch('wazuh.analysisd.set_reload_ruleset_flag')
async def test_reload_ruleset_worker_nok(mock_set_reload_flag, mock_local_client):
    """Test reload_ruleset() for worker node with error in reload."""
    mock_set_reload_flag.side_effect = WazuhError(1914)
    result = await reload_ruleset()
    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_failed_items == 1
