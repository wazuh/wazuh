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


@pytest.mark.parametrize('agents_list, expected_socket_response, expected_result', [
    (None,
     {'timestamp': 1658400850,
      'uptime': 1658400850,
      'stats': 'value'},
     {'timestamp': datetime(2022, 7, 21, 10, 54, 10, tzinfo=timezone.utc),
      'uptime': datetime(2022, 7, 21, 10, 54, 10, tzinfo=timezone.utc),
      'stats': 'value'}),

    ([1, 2, 3],
     {'timestamp': 1658400850,
      'agents': [{'id': agent_id, 'uptime': 1658400850} for agent_id in [1, 2, 3]]},
     {'timestamp': datetime(2022, 7, 21, 10, 54, 10, tzinfo=timezone.utc),
      'agents': [{'id': agent_id, 'uptime': datetime(2022, 7, 21, 10, 54, 10, tzinfo=timezone.utc)} for agent_id in
                 [1, 2, 3]]}),

    ('all',
     {'data': {'timestamp': 1658400850,
               'agents': [{'id': agent_id, 'uptime': 1658400850} for agent_id in [1, 2, 3]]}},
     {'data': {'timestamp': datetime(2022, 7, 21, 10, 54, 10, tzinfo=timezone.utc),
               'agents': [{'id': agent_id, 'uptime': datetime(2022, 7, 21, 10, 54, 10, tzinfo=timezone.utc)} for
                          agent_id in [1, 2, 3]]}})
])
@patch('wazuh.core.wazuh_socket.WazuhSocketJSON.close')
@patch('wazuh.core.wazuh_socket.WazuhSocketJSON.send')
@patch('wazuh.core.wazuh_socket.WazuhSocketJSON.__init__', return_value=None)
def test_get_daemons_stats_socket(mock__init__, mock_send, mock_close, agents_list, expected_socket_response,
                                  expected_result):
    """Verify get_daemons_stats_socket(socket : str) function works as expected"""
    socket = '/test_path/socket'
    expected_msg = {'version': 1, 'origin': {'module': 'framework'},
                    'command': 'getagentsstats' if agents_list else 'getstats'}
    if agents_list:
        expected_msg |= {'parameters': {'agents': agents_list}}
        if agents_list == 'all':
            expected_msg['parameters'] |= {'last_id': 0}

    with patch('wazuh.core.wazuh_socket.WazuhSocketJSON.receive',
               return_value=expected_socket_response) as mock_receive:
        result = stats.get_daemons_stats_socket(socket, agents_list=agents_list,
                                                last_id=0 if agents_list == 'all' else None)

        mock__init__.assert_called_once_with(socket)
        mock_send.assert_called_once_with(expected_msg)
        mock_receive.assert_called_once()
        mock_close.assert_called_once()
        assert result == expected_result


@pytest.mark.parametrize('agents_list', [
    None, [1, 2, 3]
])
def test_get_daemons_stats_socket_ko(agents_list):
    """Test get_daemons_stats_socket(socket : str) function exception works"""
    socket = '/test_path/socket'
    with pytest.raises(WazuhInternalError, match=f".* 1121 .*: {socket}"):
        stats.get_daemons_stats_socket(socket, agents_list=agents_list)
