# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.core import stats
        from wazuh.core.exception import WazuhInternalError
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser


@patch('wazuh.core.wazuh_socket.WazuhSocketJSON.close')
@patch('wazuh.core.wazuh_socket.WazuhSocketJSON.send')
@patch('wazuh.core.wazuh_socket.WazuhSocketJSON.__init__', return_value=None)
def test_get_daemons_stats_socket(mock__init__, mock_send, mock_close):
    """Verify get_daemons_stats_socket(socket : str) function works as expected"""
    socket = '/test_path/socket'
    expected_msg = {'version': 1, 'origin': {'module': 'framework'}, 'command': 'getstats'}
    expected_socket_response = {'timestamp': 1658400850, 'uptime': 1658400850, 'stats': 'value'}
    expected_result = {'timestamp': datetime(2022, 7, 21, 10, 54, 10, tzinfo=timezone.utc),
                       'uptime': datetime(2022, 7, 21, 10, 54, 10, tzinfo=timezone.utc),
                       'stats': 'value'}

    with patch('wazuh.core.wazuh_socket.WazuhSocketJSON.receive',
               return_value=expected_socket_response) as mock_receive:
        result = stats.get_daemons_stats_socket(socket)

        mock__init__.assert_called_once_with(socket)
        mock_send.assert_called_once_with(expected_msg)
        mock_receive.assert_called_once()
        mock_close.assert_called_once()
        assert result == expected_result


def test_get_daemons_stats_socket_ko():
    """Test get_daemons_stats_socket(socket : str) function exception works"""
    socket = '/test_path/socket'
    with pytest.raises(WazuhInternalError, match=f".* 1121 .*: {socket}"):
        stats.get_daemons_stats_socket(socket)
