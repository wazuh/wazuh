# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import socket
import threading
from struct import pack, unpack
from unittest.mock import patch, MagicMock

import pytest

from wazuh.core.exception import WazuhException
from wazuh.core.wazuh_socket import WazuhSocket, WazuhSocketJSON, \
    SOCKET_COMMUNICATION_PROTOCOL_VERSION, create_wazuh_socket_message, daemons, wazuh_sendsync


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


@pytest.fixture
def fake_authd(tmp_path):
    """Serve the authd framing from a thread, so that an exchange which blocks the event loop fails its
    test instead of hanging it. Yields a dict: set 'delay' to answer late, 'answer' to the chunks sent as the answer
    (sent 0.05 seconds apart), read 'requests' for what arrived."""
    path = str(tmp_path / 'auth')
    state = {'delay': 0, 'answer': [pack('<I', 2) + b'ok'], 'requests': []}
    stop = threading.Event()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen()
    server.settimeout(0.05)

    def serve():
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            with conn:
                size = unpack('<I', conn.recv(4, socket.MSG_WAITALL))[0]
                state['requests'].append(conn.recv(size, socket.MSG_WAITALL).decode())
                if not stop.wait(state['delay']):
                    for chunk in state['answer']:
                        conn.sendall(chunk)
                        stop.wait(0.05)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    with patch.dict(daemons['authd'], path=path):
        yield state
    stop.set()
    thread.join()
    server.close()


@pytest.mark.parametrize('message, received', [('{"function": "add"}', '{"function": "add"}'),
                                                ({'function': 'add'}, '{"function": "add"}')])
async def test_wazuh_sendsync(fake_authd, message, received):
    """The daemon gets the message, as a string or serialized from a dict, and its answer is returned."""
    assert await wazuh_sendsync('authd', message, timeout=5) == 'ok'
    assert fake_authd['requests'] == [received]


async def test_wazuh_sendsync_does_not_block_the_loop(fake_authd):
    """While the daemon takes its time to answer, the other tasks of the loop keep running."""
    fake_authd['delay'] = 0.5
    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.01)
            ticks += 1

    task = asyncio.create_task(ticker())
    assert await wazuh_sendsync('authd', 'request', timeout=5) == 'ok'
    task.cancel()
    assert ticks >= 10


async def test_wazuh_sendsync_answer_in_pieces(fake_authd):
    """An answer that arrives in several pieces is read whole."""
    fake_authd['answer'] = [pack('<I', 7) + b'ok', b' done']
    assert await wazuh_sendsync('authd', 'request', timeout=5) == 'ok done'


async def test_wazuh_sendsync_truncated_answer(fake_authd):
    """An answer shorter than its header says is error 1014."""
    fake_authd['answer'] = [pack('<I', 6) + b'ok']
    with pytest.raises(WazuhException, match='.* 1014 .*'):
        await wazuh_sendsync('authd', 'request', timeout=5)


async def test_wazuh_sendsync_timeout(fake_authd):
    """A daemon that does not answer in time ends the exchange with error 1014."""
    fake_authd['delay'] = 5
    with pytest.raises(WazuhException, match='.* 1014 .*no answer from authd in 0.1 seconds'):
        await wazuh_sendsync('authd', 'request', timeout=0.1)


async def test_wazuh_sendsync_ko(tmp_path):
    """A missing socket is error 1013, one nobody listens on 1121, and anything else 1014."""
    path = str(tmp_path / 'auth')
    with patch.dict(daemons['authd'], path=path):
        with pytest.raises(WazuhException, match='.* 1013 .*'):
            await wazuh_sendsync('authd', 'request')

        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).bind(path)
        with pytest.raises(WazuhException, match='.* 1121 .*'):
            await wazuh_sendsync('authd', 'request')

    with pytest.raises(WazuhException, match='.* 1014 .*'):
        await wazuh_sendsync('unknown_daemon', 'request')
