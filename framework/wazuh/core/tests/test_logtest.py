# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import pytest

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        from wazuh.core.logtest import send_logtest_msg
        from wazuh.core.common import LOGTEST_SOCKET


@pytest.mark.parametrize('params', [
    {'command': 'random_command', 'parameters': {'param1': 'value1'}},
    {'command': None, 'parameters': None}
])
@patch('wazuh.core.logtest.OssecSocketJSON.__init__', return_value=None)
@patch('wazuh.core.logtest.OssecSocketJSON.send')
@patch('wazuh.core.logtest.OssecSocketJSON.close')
@patch('wazuh.core.logtest.create_wazuh_socket_message')
def test_send_logtest_msg(create_message_mock, close_mock, send_mock, init_mock, params):
    """Test `send_logtest_msg` function from module core.logtest.

    Parameters
    ----------
    message : dict
        Message that will be sent to the logtest socket.
    """
    expected_response = {'response': True}
    with patch('wazuh.core.logtest.OssecSocketJSON.receive', return_value=expected_response):
        response = send_logtest_msg(**params)
        init_mock.assert_called_with(LOGTEST_SOCKET)
        create_message_mock.assert_called_with(origin={'name': 'Logtest', 'module': 'api/framework'}, **params)
        assert response == expected_response

