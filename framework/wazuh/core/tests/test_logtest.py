# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import pytest

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        from wazuh.core.logtest import send_logtest_msg
        from wazuh.core.common import LOGTEST_SOCKET


@pytest.mark.parametrize('message', [
    {'random': 'msg'},
    {'token': 'arandomtoken123', 'event': 'arandomevent', 'log': 'arandomlog'},
    {}
])
@patch('wazuh.core.logtest.OssecSocketJSON.__init__', return_value=None)
@patch('wazuh.core.logtest.OssecSocketJSON.send')
@patch('wazuh.core.logtest.OssecSocketJSON.close')
def test_send_logtest_msg(close_mock, send_mock, init_mock, message):
    """Test `send_logtest_msg` function from module core.logtest.

    Parameters
    ----------
    message : dict
        Message that will be sent to the logtest socket.
    """
    expected_response = {'response': True}
    with patch('wazuh.core.logtest.OssecSocketJSON.receive', return_value=expected_response):
        response = send_logtest_msg(message)
        init_mock.assert_called_with(LOGTEST_SOCKET)
        assert response == expected_response
