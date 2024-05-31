# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch, MagicMock, AsyncMock

import pytest
from wazuh.core.exception import WazuhException
from wazuh.core.wazuh_socket import WazuhSocket, WazuhSocketJSON, WazuhAsyncSocket, WazuhAsyncProtocol, \
    SOCKET_COMMUNICATION_PROTOCOL_VERSION, create_wazuh_socket_message


class LoopMock:

    def __init__(self):
        pass

    @staticmethod
    async def create_connection(protocol_factory, sock):
        with patch('asyncio.transports.Transport') as transport:
            return transport, WazuhAsyncProtocol(LoopMock())

    def set_exception_handler(self, exc_handler):
        pass

    def create_future(self):
        pass


class ProtocolMock:
        def __init__(self):
            self.on_data_received = ProtocolMock.testing()

        @staticmethod
        async def testing():
            return 'test'
        
        @staticmethod
        def get_data():
            return b'data'


@patch('wazuh.core.wazuh_socket.WazuhSocket._connect')
def test_WazuhSocket__init__(mock_conn):
    """Tests WazuhSocket.__init__ function works"""

    WazuhSocket('test_path')

    mock_conn.assert_called_once_with()


@patch('wazuh.core.wazuh_socket.socket.socket.connect')
def test_WazuhSocket_protected_connect(mock_conn):
    """Tests WazuhSocket._connect function works"""

    WazuhSocket('test_path')

    mock_conn.assert_called_with('test_path')


@patch('wazuh.core.wazuh_socket.socket.socket.connect', side_effect=Exception)
def test_WazuhSocket_protected_connect_ko(mock_conn):
    """Tests WazuhSocket._connect function exceptions works"""

    with pytest.raises(WazuhException, match=".* 1013 .*"):
        WazuhSocket('test_path')


@patch('wazuh.core.wazuh_socket.socket.socket.connect')
@patch('wazuh.core.wazuh_socket.socket.socket.close')
def test_WazuhSocket_close(mock_close, mock_conn):
    """Tests WazuhSocket.close function works"""

    queue = WazuhSocket('test_path')

    queue.close()

    mock_conn.assert_called_once_with('test_path')
    mock_close.assert_called_once_with()


@patch('wazuh.core.wazuh_socket.socket.socket.connect')
@patch('wazuh.core.wazuh_socket.socket.socket.send')
def test_WazuhSocket_send(mock_send, mock_conn):
    """Tests WazuhSocket.send function works"""

    queue = WazuhSocket('test_path')

    response = queue.send(b"\x00\x01")

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@pytest.mark.parametrize('msg, effect, send_effect, expected_exception', [
    ('text_msg', 'side_effect', None, 1105),
    (b"\x00\x01", 'return_value', 0, 1014),
    (b"\x00\x01", 'side_effect', Exception, 1014)
])
@patch('wazuh.core.wazuh_socket.socket.socket.connect')
def test_WazuhSocket_send_ko(mock_conn, msg, effect, send_effect, expected_exception):
    """Tests WazuhSocket.send function exceptions works"""

    queue = WazuhSocket('test_path')

    if effect == 'return_value':
        with patch('wazuh.core.wazuh_socket.socket.socket.send', return_value=send_effect):
            with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
                queue.send(msg)
    else:
        with patch('wazuh.core.wazuh_socket.socket.socket.send', side_effect=send_effect):
            with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
                queue.send(msg)

    mock_conn.assert_called_once_with('test_path')


@patch('wazuh.core.wazuh_socket.socket.socket.connect')
@patch('wazuh.core.wazuh_socket.unpack', return_value='1024')
@patch('wazuh.core.wazuh_socket.socket.socket.recv')
def test_WazuhSocket_receive(mock_recv, mock_unpack, mock_conn):
    """Tests WazuhSocket.receive function works"""

    queue = WazuhSocket('test_path')

    response = queue.receive()

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@patch('wazuh.core.wazuh_socket.socket.socket.connect')
@patch('wazuh.core.wazuh_socket.socket.socket.recv', side_effect=Exception)
def test_WazuhSocket_receive_ko(mock_recv, mock_conn):
    """Tests WazuhSocket.receive function exception works"""

    queue = WazuhSocket('test_path')

    with pytest.raises(WazuhException, match=".* 1014 .*"):
        queue.receive()

    mock_conn.assert_called_once_with('test_path')


@patch('wazuh.core.wazuh_socket.WazuhSocket._connect')
def test_WazuhSocketJSON__init__(mock_conn):
    """Tests WazuhSocketJSON.__init__ function works"""

    WazuhSocketJSON('test_path')

    mock_conn.assert_called_once_with()


@patch('wazuh.core.wazuh_socket.socket.socket.connect')
@patch('wazuh.core.wazuh_socket.WazuhSocket.send')
def test_WazuhSocketJSON_send(mock_send, mock_conn):
    """Tests WazuhSocketJSON.send function works"""

    queue = WazuhSocketJSON('test_path')

    response = queue.send('test_msg')

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@pytest.mark.parametrize('raw', [
    True, False
])
@patch('wazuh.core.wazuh_socket.socket.socket.connect')
@patch('wazuh.core.wazuh_socket.WazuhSocket.receive')
@patch('wazuh.core.wazuh_socket.loads', return_value={'error':0, 'message':None, 'data':'Ok'})
def test_WazuhSocketJSON_receive(mock_loads, mock_receive, mock_conn, raw):
    """Tests WazuhSocketJSON.receive function works"""
    queue = WazuhSocketJSON('test_path')
    response = queue.receive(raw=raw)
    if raw:
        assert isinstance(response, dict)
    else:
        assert isinstance(response, str)
    mock_conn.assert_called_once_with('test_path')


@patch('wazuh.core.wazuh_socket.socket.socket.connect')
@patch('wazuh.core.wazuh_socket.WazuhSocket.receive')
@patch('wazuh.core.wazuh_socket.loads', return_value={'error':10000, 'message':'Error', 'data':'KO'})
def test_WazuhSocketJSON_receive_ko(mock_loads, mock_receive, mock_conn):
    """Tests WazuhSocketJSON.receive function works"""

    queue = WazuhSocketJSON('test_path')

    with pytest.raises(WazuhException, match=".* 10000 .*"):
        queue.receive()

    mock_conn.assert_called_once_with('test_path')


@pytest.mark.parametrize('origin, command, parameters', [
    ('origin_sample', 'command_sample', {'sample': 'sample'}),
    (None, 'command_sample', {'sample': 'sample'}),
    ('origin_sample', None, {'sample': 'sample'}),
    ('origin_sample', 'command_sample', None),
    (None, None, None)
])
def test_create_wazuh_socket_message(origin, command, parameters):
    """Test create_wazuh_socket_message function."""
    response_message = create_wazuh_socket_message(origin, command, parameters)
    assert response_message['version'] == SOCKET_COMMUNICATION_PROTOCOL_VERSION
    assert response_message.get('origin') == origin
    assert response_message.get('command') == command
    assert response_message.get('parameters') == parameters


@pytest.mark.asyncio
@patch('wazuh.core.wazuh_socket.socket.socket.connect')
async def test_WazuhAsyncSocket_connect(mock_conn):
    """Tests WazuhAsyncSocket.connect function works."""
    path = 'test_path'
    socket =  WazuhAsyncSocket()
    await socket.connect(path)
    mock_conn.assert_called_once_with(path)


@pytest.mark.asyncio
@patch('wazuh.core.wazuh_socket.socket.socket.connect', side_effect=ValueError)
async def test_WazuhAsyncSocket_connect_ko(mock_conn):
    """Tests WazuhAsyncSocket.connect function exceptions works."""
    with pytest.raises(WazuhException, match=".* 1013 .*"):
        socket = WazuhAsyncSocket()
        await socket.connect('test_path')


@pytest.mark.asyncio
@patch('wazuh.core.wazuh_socket.socket.socket.connect')
@patch('wazuh.core.wazuh_socket.socket.socket.close')
async def test_WazuhAsyncSocket_close(mock_close, mock_conn):
    """Tests WazuhAsyncSocket.close function works."""
    socket = WazuhAsyncSocket()
    await socket.connect('test_path')
    await socket.close()
    mock_close.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize('header_format, expected_response', [
    (None, b'\x00\x01'),
    ('?', b'\x01\x00\x01'),
    ('h', b'\x02\x00\x00\x01'),
    ('i', b'\x02\x00\x00\x00\x00\x01'),
    ('l', b'\x02\x00\x00\x00\x00\x00\x00\x00\x00\x01'),
    ('q', b'\x02\x00\x00\x00\x00\x00\x00\x00\x00\x01'),
    ('f', b'\x00\x00\x00@\x00\x01'),
])
@patch('wazuh.core.wazuh_socket.socket.socket.connect')
@patch('asyncio.Transport.write')
@patch('wazuh.core.wazuh_socket.WazuhAsyncSocket.is_connection_lost', return_value=False)
async def test_WazuhAsyncSocket_send(mock_conn_lost, mock_write, mock_conn, header_format, expected_response):
    """Tests WazuhAsyncSocket.send function works."""
    socket = WazuhAsyncSocket()
    await socket.connect('test_path')

    data = b'\x00\x01'
    response = await socket.send(data, header_format)

    assert response == expected_response


@pytest.mark.asyncio
@pytest.mark.parametrize('msg, effect, send_effect, expected_exception', [
    ('text_msg', 'side_effect', None, 1105),
    (b"\x00\x01", 'return_value', 0, 1014),
    (b"\x00\x01", 'side_effect', Exception, 1014)
])
@patch('wazuh.core.wazuh_socket.socket.socket.connect')
async def test_WazuhAsyncSocket_send_ko(mock_conn, msg, effect, send_effect, expected_exception):
    """Tests WazuhAsyncSocket.send function exceptions works."""
    socket = WazuhAsyncSocket()
    await socket.connect('test_path')

    if effect == 'return_value':
        with patch('asyncio.transports.Transport.write', return_value=send_effect):
            with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
                await socket.send(msg)
    else:
        with patch('asyncio.transports.Transport.write', side_effect=send_effect):
            with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
                await socket.send(msg)

    mock_conn.assert_called_once_with('test_path')


@pytest.mark.asyncio
@pytest.mark.parametrize('header_size', [None, 0, 2, 4])
@patch('wazuh.core.wazuh_socket.socket.socket.connect')
async def test_WazuhAsyncSocket_receive(mock_conn, header_size):
    """Tests WazuhAsyncSocket.receive function works."""
    socket = WazuhAsyncSocket()
    await socket.connect('test_path')
    socket.protocol = ProtocolMock()

    response = await socket.receive(header_size)
    data = socket.protocol.get_data()
    if header_size is None:
        assert response == data
        assert len(response) == len(data)
    else:
        assert response == data[header_size:]
        assert len(response) == len(data) - header_size


@pytest.mark.asyncio
@patch('wazuh.core.wazuh_socket.socket.socket.connect')
@patch('asyncio.get_running_loop', return_value=LoopMock)
async def test_WazuhAsyncSocket_receive_ko(mock_running_loop, mock_conn):
    """Tests WazuhAsyncSocket.receive function exception works."""
    socket = WazuhAsyncSocket()
    await socket.connect('test_path')

    with pytest.raises(WazuhException, match=".* 1014 .*"):
        await socket.receive()
