# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
import pytest

from wazuh.core.ossec_queue import OssecQueue
from wazuh.core.exception import WazuhException


@patch('wazuh.core.ossec_queue.OssecQueue._connect')
def test_OssecQueue__init__(mock_conn):
    """Tests OssecQueue.__init__ function works"""

    OssecQueue('test_path')

    mock_conn.assert_called_once_with()


@patch('wazuh.core.ossec_queue.socket.socket.connect')
@patch('wazuh.core.ossec_queue.socket.socket.setsockopt')
def test_OssecQueue_protected_connect(mock_set, mock_conn):
    """Tests OssecQueue._connect function works"""

    OssecQueue('test_path')

    with patch('wazuh.core.ossec_queue.socket.socket.getsockopt', return_value=1):
        OssecQueue('test_path')

    mock_conn.assert_called_with('test_path')
    mock_set.assert_called_once_with(1, 7, 6400)


@patch('wazuh.core.ossec_queue.socket.socket.connect', side_effect=Exception)
def test_OssecQueue_protected_connect_ko(mock_conn):
    """Tests OssecQueue._connect function exceptions works"""

    with pytest.raises(WazuhException, match=".* 1010 .*"):
        OssecQueue('test_path')


@pytest.mark.parametrize('send_response, error', [
    (1, False),
    (0, True)
])
@patch('wazuh.core.ossec_queue.socket.socket.connect')
@patch('wazuh.core.ossec_queue.OssecQueue.MAX_MSG_SIZE', new=0)
def test_OssecQueue_protected_send(mock_conn, send_response, error):
    """Tests OssecQueue._send function works"""

    queue = OssecQueue('test_path')

    with patch('socket.socket.send', return_value=send_response):
        if error:
            with pytest.raises(WazuhException, match=".* 1011 .*"):
                queue._send('msg')
        else:
            queue._send('msg')

    mock_conn.assert_called_with('test_path')


@patch('wazuh.core.ossec_queue.socket.socket.connect')
@patch('wazuh.core.ossec_queue.OssecQueue.MAX_MSG_SIZE', new=0)
@patch('socket.socket.send', side_effect=Exception)
def test_OssecQueue_protected_send_ko(mock_send, mock_conn):
    """Tests OssecQueue._send function exceptions works"""

    queue = OssecQueue('test_path')

    with pytest.raises(WazuhException, match=".* 1011 .*"):
        queue._send('msg')

    mock_conn.assert_called_with('test_path')


@patch('wazuh.core.ossec_queue.socket.socket.connect')
@patch('wazuh.core.ossec_queue.socket.socket.close')
def test_OssecQueue_close(mock_close, mock_conn):
    """Tests OssecQueue.close function works"""

    queue = OssecQueue('test_path')

    queue.close()

    mock_conn.assert_called_once_with('test_path')
    mock_close.assert_called_once_with()


@pytest.mark.parametrize('msg, agent_id, msg_type', [
    ('test_msg', '000', 'ar-message'),
    ('test_msg', '001', 'ar-message'),
    ('test_msg', None, 'ar-message'),
    ('syscheck restart', '000', None),
    ('restart-ossec0', '001', None),
    ('syscheck restart', None, None),
    ('restart-ossec0', None, None)
])
@patch('wazuh.core.ossec_queue.socket.socket.connect')
@patch('wazuh.core.ossec_queue.OssecQueue._send')
def test_OssecQueue_send_msg_to_agent(mock_send, mock_conn, msg, agent_id, msg_type):
    """Tests OssecQueue.send_msg_to_agent function works"""

    queue = OssecQueue('test_path')

    response = queue.send_msg_to_agent(msg, agent_id, msg_type)

    assert isinstance(response, str)
    mock_conn.assert_called_once_with('test_path')


@pytest.mark.parametrize('msg, agent_id, msg_type, expected_exception', [
    ('test_msg', '000', 'ar-message', 1652),
    ('test_msg', '000', None, 1012),
    ('syscheck restart', '001', None, 1601),
    ('syscheck restart', None, None, 1601),
    ('restart-ossec0', None, None, 1702)
])
@patch('wazuh.core.ossec_queue.socket.socket.connect')
@patch('wazuh.core.ossec_queue.OssecQueue._send', side_effect=Exception)
def test_OssecQueue_send_msg_to_agent_ko(mock_send, mock_conn, msg, agent_id, msg_type, expected_exception):
    """Tests OssecQueue.send_msg_to_agent function exception works"""

    queue = OssecQueue('test_path')

    with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
        queue.send_msg_to_agent(msg, agent_id, msg_type)

    mock_conn.assert_called_once_with('test_path')
