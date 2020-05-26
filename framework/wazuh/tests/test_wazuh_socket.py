# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch, MagicMock, Mock

import asyncio
import pytest

from struct import pack
from wazuh.wazuh_socket import OssecSocket, OssecSocketJSON, WazuhAsyncProtocol, WazuhAsyncSocket, WazuhSocketJSON, send_sync, daemons
from wazuh.exception import WazuhException


# OssecSocket Tests

@patch('wazuh.wazuh_socket.OssecSocket._connect')
def test_OssecSocket__init__(mock_conn):
    """Tests OssecSocket.__init__ function works"""

    OssecSocket('test_path')

    mock_conn.assert_called_once_with()


@patch('wazuh.wazuh_socket.socket.socket.connect')
def test_OssecSocket_protected_connect(mock_conn):
    """Tests OssecSocket._connect function works"""

    OssecSocket('test_path')

    mock_conn.assert_called_with('test_path')


@patch('wazuh.wazuh_socket.socket.socket.connect', side_effect=Exception)
def test_OssecSocket_protected_connect_ko(mock_conn):
    """Tests OssecSocket._connect function exceptions works"""

    with pytest.raises(WazuhException, match=".* 1013 .*"):
        OssecSocket('test_path')


@patch('wazuh.wazuh_socket.socket.socket.connect')
@patch('wazuh.wazuh_socket.socket.socket.close')
def test_OssecSocket_close(mock_close, mock_conn):
    """Tests OssecSocket.close function works"""

    queue = OssecSocket('test_path')

    queue.close()

    mock_conn.assert_called_once_with('test_path')
    mock_close.assert_called_once_with()


@patch('wazuh.wazuh_socket.socket.socket.connect')
@patch('wazuh.wazuh_socket.socket.socket.send')
def test_OssecSocket_send(mock_send, mock_conn):
    """Tests OssecSocket.send function works"""

    queue = OssecSocket('test_path')

    response = queue.send(b"\x00\x01")

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@pytest.mark.parametrize('msg, effect, send_effect, expected_exception', [
    ('text_msg', 'side_effect', None, 1105),
    (b"\x00\x01", 'return_value', 0, 1014),
    (b"\x00\x01", 'side_effect', Exception, 1014)
])
@patch('wazuh.wazuh_socket.socket.socket.connect')
def test_OssecSocket_send_ko(mock_conn, msg, effect, send_effect, expected_exception):
    """Tests OssecSocket.send function exceptions works"""

    queue = OssecSocket('test_path')

    if effect == 'return_value':
        with patch('wazuh.wazuh_socket.socket.socket.send', return_value=send_effect):
            with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
                queue.send(msg)
    else:
        with patch('wazuh.wazuh_socket.socket.socket.send', side_effect=send_effect):
            with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
                queue.send(msg)

    mock_conn.assert_called_once_with('test_path')


@patch('wazuh.wazuh_socket.socket.socket.connect')
@patch('wazuh.wazuh_socket.unpack', return_value='1024')
@patch('wazuh.wazuh_socket.socket.socket.recv')
def test_OssecSocket_receive(mock_recv, mock_unpack, mock_conn):
    """Tests OssecSocket.receive function works"""

    queue = OssecSocket('test_path')

    response = queue.receive()

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@patch('wazuh.wazuh_socket.socket.socket.connect')
@patch('wazuh.wazuh_socket.socket.socket.recv', side_effect=Exception)
def test_OssecSocket_receive_ko(mock_recv, mock_conn):
    """Tests OssecSocket.receive function exception works"""

    queue = OssecSocket('test_path')

    with pytest.raises(WazuhException, match=".* 1014 .*"):
        queue.receive()

    mock_conn.assert_called_once_with('test_path')


@patch('wazuh.wazuh_socket.OssecSocket._connect')
def test_OssecSocketJSON__init__(mock_conn):
    """Tests OssecSocketJSON.__init__ function works"""

    OssecSocketJSON('test_path')

    mock_conn.assert_called_once_with()


@patch('wazuh.wazuh_socket.socket.socket.connect')
@patch('wazuh.wazuh_socket.OssecSocket.send')
def test_OssecSocketJSON_send(mock_send, mock_conn):
    """Tests OssecSocketJSON.send function works"""

    queue = OssecSocketJSON('test_path')

    response = queue.send('test_msg')

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@patch('wazuh.wazuh_socket.socket.socket.connect')
@patch('wazuh.wazuh_socket.OssecSocket.receive')
@patch('wazuh.wazuh_socket.loads', return_value={'error':0, 'message':None, 'data':'Ok'})
def test_OssecSocketJSON_receive(mock_loads, mock_receive, mock_conn):
    """Tests OssecSocketJSON.receive function works"""

    queue = OssecSocketJSON('test_path')

    response = queue.receive()

    assert isinstance(response, str)
    mock_conn.assert_called_once_with('test_path')


@patch('wazuh.wazuh_socket.socket.socket.connect')
@patch('wazuh.wazuh_socket.OssecSocket.receive')
@patch('wazuh.wazuh_socket.loads', return_value={'error':10000, 'message':'Error', 'data':'KO'})
def test_OssecSocketJSON_receive_ko(mock_loads, mock_receive, mock_conn):
    """Tests OssecSocketJSON.receive function works"""

    queue = OssecSocketJSON('test_path')

    with pytest.raises(WazuhException, match=".* 10000 .*"):
        queue.receive()

    mock_conn.assert_called_once_with('test_path')


# WazuhSocket Tests

@patch('wazuh.wazuh_socket.socket.socket.connect')
def test_wazuh_async_socket_connect(mock_conn):
    """Test WazuhSocket.connect function works as expected."""
    socket = WazuhAsyncSocket()
    asyncio.run(socket.connect('test_path'))
    mock_conn.assert_called_with('test_path')
    assert socket.s
    assert socket.loop
    assert socket.transport
    assert socket.protocol
    asyncio.run(socket.close())


@pytest.mark.parametrize('side_effect', [ValueError, FileNotFoundError])
@patch('wazuh.wazuh_socket.socket.socket.connect')
def test_wazuh_async_socket_connect_ko(mock_conn, side_effect):
    """Test WazuhAsyncSocket.connect function raises the expected exceptions."""
    socket = WazuhAsyncSocket()
    mock_conn.side_effect = side_effect
    with pytest.raises(WazuhException, match=".* 1013 .*"):
        asyncio.run(socket.connect('test_path'))


@pytest.mark.parametrize('msg_bytes, header_format', [
    (b'Test_msg', "<I"),
    (b'Test_msg', None)
])
@patch('wazuh.wazuh_socket.socket.socket.connect')
def test_wazuh_async_socket_send(mock_conn, msg_bytes, header_format):
    """Test WazuhAsyncSocket.send function works as expected."""
    socket = WazuhAsyncSocket()
    asyncio.run(socket.connect('test_path'))
    mock_conn.assert_called_with('test_path')

    socket.transport.write = asyncio.coroutine(Mock)
    sent = asyncio.run(socket.send(msg_bytes, header_format))
    mock_conn.assert_called_once_with('test_path')
    expected_data = pack(header_format, len(msg_bytes)) + msg_bytes if header_format else msg_bytes
    assert sent == expected_data


@pytest.mark.parametrize('msg_bytes, expected_match', [
    ('', '.* 1105 .*'),
    (b'', '.* 1014 .*')
])
@patch('wazuh.wazuh_socket.socket.socket.connect')
def test_wazuh_async_socket_send_ko(mock_conn, msg_bytes, expected_match):
    """Test WazuhAsyncSocket.send function works as expected."""
    socket = WazuhAsyncSocket()
    asyncio.run(socket.connect('test_path'))
    mock_conn.assert_called_with('test_path')

    socket.transport.write = asyncio.coroutine(Mock)

    with pytest.raises(WazuhException, match=expected_match):
        asyncio.run(socket.send(msg_bytes))


@pytest.mark.parametrize('header_size', [0, 4])
@patch('wazuh.wazuh_socket.socket.socket.connect')
@patch('wazuh.wazuh_socket.WazuhAsyncProtocol.get_data')
def test_wazuh_async_socket_receive(mock_get_data, mock_conn, header_size):
    """Test WazuhAsyncSocket.receive function works as expected."""
    async def test():
        expected_msg = b'test message'
        mock_get_data.return_value = expected_msg

        socket = WazuhAsyncSocket()
        await socket.connect('test_path')

        loop = asyncio.get_running_loop()
        socket.protocol.on_data_received = loop.create_future()
        socket.protocol.on_data_received.set_result(True)
        response = await socket.receive(header_size=header_size)

        mock_get_data.assert_called_once()
        assert response == expected_msg[header_size:]

    asyncio.run(test())


@patch('wazuh.wazuh_socket.socket.socket.connect')
@patch('wazuh.wazuh_socket.WazuhAsyncProtocol.get_data', side_effect=Exception)
def test_wazuh_async_socket_receive_ko(mock_recv, mock_conn):
    """Test WazuhAsyncSocket.receive function exception works as expected."""
    async def test():
        socket = WazuhAsyncSocket()
        await socket.connect('test_path')

        loop = asyncio.get_running_loop()
        socket.protocol.on_data_received = loop.create_future()
        socket.protocol.on_data_received.set_result(True)

        with pytest.raises(WazuhException, match=".* 1014 .*"):
            await socket.receive()

    asyncio.run(test())


# WazuhSocketJSON tests

@patch('wazuh.wazuh_socket.socket.socket.connect')
def test_wazuh_async_socket_json_send(mock_conn):
    """Test WazuhAsyncSocketJSON.send function works as expected."""
    def assert_msg(msg):
        assert isinstance(msg, bytes)

    socket = WazuhSocketJSON()
    asyncio.run(socket.connect('test_path'))
    mock_conn.assert_called_with('test_path')

    socket.transport.write = asyncio.coroutine(assert_msg)
    asyncio.run(socket.send('{"error":1, "message": "error"}'))


@patch('wazuh.wazuh_socket.socket.socket.connect')
@patch('wazuh.wazuh_socket.WazuhAsyncSocket.receive')
def test_wazuh_async_socket_json_receive(mock_receive, mock_conn):
    """Test WazuhAsyncSocketJSON.receive function works as expected."""
    mock = Mock(return_value=b'{"error":0, "data": "example"}')
    mock_receive.side_effect = asyncio.coroutine(mock)

    socket = WazuhSocketJSON()
    asyncio.run(socket.connect('test_path'))
    result = asyncio.run(socket.receive())
    mock_receive.assert_called_once()
    assert result == "example"


@patch('wazuh.wazuh_socket.socket.socket.connect')
@patch('wazuh.wazuh_socket.WazuhAsyncSocket.receive')
def test_wazuh_async_socket_json_receive_ko(mock_receive, mock_conn):
    """Test WazuhAsyncSocketJSON.receive function works as expected."""
    mock = Mock(return_value=b'{"error":1, "message": "example"}')
    mock_receive.side_effect = asyncio.coroutine(mock)

    socket = WazuhSocketJSON()
    asyncio.run(socket.connect('test_path'))

    with pytest.raises(WazuhException):
        asyncio.run(socket.receive())


@pytest.mark.parametrize("daemon_name", ["authd"])
@patch('wazuh.wazuh_socket.WazuhSocketJSON.connect', side_effect=asyncio.coroutine(Mock))
@patch('wazuh.wazuh_socket.WazuhSocketJSON.send', side_effect=asyncio.coroutine(Mock))
@patch('wazuh.wazuh_socket.WazuhSocketJSON.receive', side_effect=asyncio.coroutine(Mock))
@patch('wazuh.wazuh_socket.WazuhSocketJSON.close', side_effect=asyncio.coroutine(Mock))
def test_send_sync(mock_close, mock_receive, mock_send, mock_connect, daemon_name):
    """Test send_sync function works as expected."""
    asyncio.run(send_sync(daemon_name))
    mock_connect.assert_called_with(daemons[daemon_name]['path'])
    mock_send.assert_called_with(None, daemons[daemon_name]['header_format'])
    mock_receive.assert_called_with(daemons[daemon_name]['size'])
    mock_close.assert_called_with()


def test_wazuh_async_protocol_data_received():
    async def test():
        loop = asyncio.get_running_loop()
        protocol = WazuhAsyncProtocol(loop)

        assert protocol.data is None
        protocol.data_received(b'test')
        assert protocol.data == b'test'

    asyncio.run(test())


def test_wazuh_async_protocol_get_data():
    async def test():
        loop = asyncio.get_running_loop()
        protocol = WazuhAsyncProtocol(loop)

        assert protocol.data is None
        protocol.data = b'test'

        data = protocol.get_data()
        assert protocol.data is None
        assert data == b'test'

    asyncio.run(test())
