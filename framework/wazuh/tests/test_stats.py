# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import call, MagicMock, patch

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        import wazuh.stats as stats
        from wazuh.core.results import AffectedItemsWazuhResult


@patch('wazuh.core.common.REMOTED_SOCKET', '/var/wazuh-manager/queue/sockets/remote')
@patch('wazuh.core.common.WDB_SOCKET', '/var/wazuh-manager/queue/db/wdb')
@patch('wazuh.stats.EngineHTTPClient')
@patch('wazuh.stats.get_daemons_stats_socket')
def test_get_daemons_stats(mock_get_daemons_stats_socket, mock_engine_client_cls):
    """Makes sure get_daemons_stats() fit with the expected."""
    mock_engine_client = MagicMock()
    mock_engine_client.get_metrics_dump.return_value = METRICS_DUMP_DATA
    mock_engine_client_cls.return_value = mock_engine_client

    response = stats.get_daemons_stats(['wazuh-manager-remoted', 'wazuh-manager-analysisd', 'wazuh-manager-db'])

    # remoted and db still use the socket; analysisd goes through EngineHTTPClient
    calls = [call('/var/wazuh-manager/queue/sockets/remote'), call('/var/wazuh-manager/queue/db/wdb')]
    mock_get_daemons_stats_socket.assert_has_calls(calls)
    mock_engine_client.get_metrics_dump.assert_called_once()
    mock_engine_client.close.assert_called_once()
    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not AffectedItemsWazuhResult type'
    assert response.total_affected_items == len(response.affected_items)


@patch('wazuh.core.common.REMOTED_SOCKET', '/var/wazuh-manager/queue/sockets/wrong_socket_name')
def test_get_daemons_stats_ko():
    """Makes sure get_daemons_stats() fit with the expected."""
    response = stats.get_daemons_stats(['wazuh-manager-remoted'])

    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not AffectedItemsWazuhResult type'
    assert response.render()['data']['failed_items'][0]['error']['code'] == 1121, 'Expected error code was not returned'


METRICS_DUMP_DATA = {
    "status": 0,
    "name": "engine",
    "uptime": 99,
    "global": [{"name": "router.queue.size", "type": 0, "enabled": True, "value": 500}],
    "spaces": [],
}


@patch('wazuh.stats.EngineHTTPClient')
def test_get_engine_metrics(mock_client_cls):
    mock_client = MagicMock()
    mock_client.get_metrics_dump.return_value = METRICS_DUMP_DATA
    mock_client_cls.return_value = mock_client

    response = stats.get_engine_metrics()

    assert isinstance(response, AffectedItemsWazuhResult)
    assert response.total_affected_items == 1
    assert response.affected_items[0] == METRICS_DUMP_DATA
    assert not response.failed_items


@patch('wazuh.stats.EngineHTTPClient')
def test_get_engine_metrics_ko(mock_client_cls):
    from wazuh.core.exception import WazuhInternalError

    mock_client = MagicMock()
    mock_client.get_metrics_dump.side_effect = WazuhInternalError(2021)
    mock_client_cls.return_value = mock_client

    response = stats.get_engine_metrics()

    assert isinstance(response, AffectedItemsWazuhResult)
    assert response.total_affected_items == 0
    assert response.render()['data']['failed_items'][0]['error']['code'] == 2021
