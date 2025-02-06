# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from asyncio import Event, Transport
from asyncio.transports import BaseTransport
from collections.abc import Callable
from unittest.mock import AsyncMock, call, patch

import pytest
from uvloop import EventLoopPolicy, new_event_loop

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        from wazuh.core.cluster.common import InBuffer
        from wazuh.core.cluster.local_client import *
        from wazuh.core.exception import WazuhInternalError

asyncio.set_event_loop_policy(EventLoopPolicy())
loop = new_event_loop()


def test_localclienthandler_initialization():
    """Check the correct initialization of the LocalClientHandler object."""
    lc = LocalClientHandler(loop=None, on_con_lost=None, name='Unittest', logger=None, manager=None, cluster_items=None)
    """Check the correct initialization of the LocalClientHandler object."""
    assert isinstance(lc.response_available, Event)
    assert lc.response == b''


def test_localclienthandler_connection_made():
    """Check that the connection_made function sets the transport parameter correctly."""
    lc = LocalClientHandler(loop=None, on_con_lost=None, name='Unittest', logger=None, manager=None, cluster_items=None)

    assert lc.transport is None
    lc.connection_made(Transport())
    assert isinstance(lc.transport, Transport)


def test_localclienthandler_cancel_all_tasks():
    """Check the proper functionality of the _cancel_all_tasks function."""
    lc = LocalClientHandler(loop=None, on_con_lost=None, name='Unittest', logger=None, manager=None, cluster_items=None)
    assert lc._cancel_all_tasks() is None


@patch('asyncio.Event.set')
def test_localclienthandler_process_request(mock_set):
    """Check each of the possible behaviors inside the _process_request function."""
    lc = LocalClientHandler(loop=None, on_con_lost=None, name='Unittest', logger=None, manager=None, cluster_items=None)
    command = b'dapi_res'
    assert lc.process_request(command=command, data=b'Error') == (b'err', b'Error')
    assert lc.process_request(command=command, data=b'Testing') == (
        b'err',
        b'Error receiving string: ID Testing not found.',
    )

    data_example = InBuffer(total=1)
    lc.in_str = {b'testing': data_example, b'test': InBuffer(total=2)}
    mock_set.reset_mock()
    assert lc.process_request(command=command, data=b'test') == (b'ok', b'Distributed api response received')
    assert lc.in_str == {b'testing': data_example}
    mock_set.assert_called_once()

    mock_set.reset_mock()
    assert lc.process_request(command=b'control_res', data=b'Error') == (b'err', b'Error')
    assert lc.in_str == {b'testing': data_example}
    mock_set.assert_called_once()

    mock_set.reset_mock()
    assert lc.process_request(command=b'control_res', data=b'test1') == (b'ok', b'Response received')
    assert lc.response == b'test1'
    mock_set.assert_called_once()

    mock_set.reset_mock()
    assert lc.process_request(command=b'dapi_err', data=b'test2') == (b'ok', b'Response received')
    assert lc.response == b'test2'
    mock_set.assert_called_once()

    mock_set.reset_mock()
    assert lc.process_request(command=b'err', data=b'test3') == (b'ok', b'Error response received')
    assert lc.response == b'test3'
    mock_set.assert_called_once()

    assert lc.process_request(command=b'another', data=b'test4') == (b'err', b"unknown command 'b'another''")


@patch('asyncio.Event.set')
def test_localclienthandler_process_error_from_peer(mock_set):
    """Run the _process_error_from_peer function and check the correct value assignment for the response attribute."""
    lc = LocalClientHandler(loop=None, on_con_lost=None, name='Unittest', logger=None, manager=None, cluster_items=None)
    assert lc.process_error_from_peer(data=b'None') == b'None'
    assert lc.response == b'None'
    mock_set.assert_called_once()


def test_localclienthandler_connection_lost():
    """Check that the set_result method of the on_con_lost object is called once with the defined parameters."""
    lc = LocalClientHandler(
        loop=None, on_con_lost=asyncio.Future(loop=loop), name='Unittest', logger=None, manager=None, cluster_items=None
    )
    with patch.object(lc.on_con_lost, 'set_result') as mock_set_result:
        lc.connection_lost(Exception())
        mock_set_result.assert_called_once_with(True)


@patch('wazuh.core.cluster.utils.get_cluster_items')
@patch('wazuh.core.cluster.utils.read_config')
@patch('wazuh.core.cluster.client.asyncio.get_running_loop')
def test_localclient_initialization(mock_get_running_loop, read_config_mock, get_cluster_items_mock):
    """Check the correct initialization of the LocalClient object."""
    lc = LocalClient()
    assert lc.request_result is None
    assert lc.protocol is None
    assert lc.transport is None


@pytest.mark.asyncio
@patch('wazuh.core.config.client.CentralizedConfig.get_server_config')
async def test_localclient_start(mock_get_server_config):
    """Check that the start method works correctly. Exceptions are not tested."""

    async def create_unix_connection(protocol_factory=None, path=None):
        return 'transport', 'protocol'

    with patch('uvloop.Loop.create_unix_connection', side_effect=create_unix_connection) as mock_create_unix_connection:
        mocked_loop = new_event_loop()
        with patch('wazuh.core.cluster.client.asyncio.get_running_loop', return_value=mocked_loop):
            lc = LocalClient()
            await lc.start()
            assert mock_create_unix_connection.call_count == 1
            assert mock_create_unix_connection.call_args[1]['path'] == common.LOCAL_SERVER_SOCKET_PATH
            assert isinstance(mock_create_unix_connection.call_args[1]['protocol_factory'], Callable)
            assert lc.protocol == 'protocol'
            assert lc.transport == 'transport'


@pytest.mark.asyncio
@patch('wazuh.core.config.client.CentralizedConfig.get_server_config')
@patch('wazuh.core.cluster.client.asyncio.get_running_loop')
async def test_localclient_start_ko(mock_get_running_loop, mock_get_server_config):
    """Check the behavior of the start function for the different types of exceptions that may occur."""
    with pytest.raises(WazuhInternalError, match=r'.* 3009 .*'):
        await LocalClient().start()

    with patch('asyncio.get_running_loop.return_value.create_unix_connection', side_effect=MemoryError):
        with pytest.raises(WazuhInternalError, match=r'.* 1119 .*'):
            await LocalClient().start()

    with patch('asyncio.get_running_loop.return_value.create_unix_connection', side_effect=FileNotFoundError):
        with pytest.raises(WazuhInternalError, match=r'.* 3012 .*'):
            await LocalClient().start()

    with patch('asyncio.get_running_loop.return_value.create_unix_connection', side_effect=ConnectionRefusedError):
        with pytest.raises(WazuhInternalError, match=r'.* 3012 .*'):
            await LocalClient().start()


@pytest.mark.asyncio
@patch('wazuh.core.cluster.utils.get_cluster_items')
@patch('wazuh.core.cluster.utils.read_config')
async def test_wait_for_response(read_config_mock, get_cluster_items_mock):
    """Verify whether keepalive messages are sent while waiting for response."""

    class Protocol:
        response = b'Async'

        def __init__(self):
            self.response_available = asyncio.Event()

    get_cluster_items_mock.return_value = {'intervals': {'worker': {'keep_alive': 1}}}
    lc = LocalClient()
    lc.protocol = Protocol()
    lc.protocol.send_request = AsyncMock()
    lc.protocol.send_request.side_effect = [b'None', exception.WazuhClusterError(3018)]

    with patch('asyncio.Event.wait', side_effect=asyncio.TimeoutError):
        with pytest.raises(WazuhInternalError, match=r'.* 3020 .*'):
            await lc.wait_for_response(timeout=200)
    lc.protocol.send_request.assert_has_calls([call(b'echo-c', b'keepalive'), call(b'echo-c', b'keepalive')])


@pytest.mark.asyncio
@patch('wazuh.core.cluster.utils.get_cluster_items')
@patch('wazuh.core.cluster.utils.read_config')
@patch('wazuh.core.cluster.client.asyncio.get_running_loop')
async def test_localclient_send_api_request(mock_get_running_loop, read_config_mock, get_cluster_items_mock):
    """Check the correct operation of the send_api_request function by mocking the protocol attribute.
    Exceptions are not tested.
    """

    class Protocol:
        def __init__(self):
            self.response_available = asyncio.Event()
            self.response = b'Async'

        async def send_request(self, data):
            return data

    get_cluster_items_mock.return_value = {
        'intervals': {'worker': {'keep_alive': 1}, 'communication': {'timeout_dapi_request': 1}}
    }
    lc = LocalClient()
    lc.protocol = Protocol()

    with patch.object(lc.protocol, 'send_request', side_effect=Protocol.send_request):
        result = b'There are no connected worker nodes'
        assert await lc.send_api_request(command=b'dapi', data=result) == {}

        result = b'Testing'
        assert await lc.send_api_request(command=b'testing', data=result) == result.decode()

        lc.protocol.response_available.set()
        assert await lc.send_api_request(command=b'dapi', data=result) == lc.protocol.response.decode()

        result = b'Sent request to master node'
        assert await lc.send_api_request(command=b'dapi', data=result) == lc.protocol.response.decode()


@pytest.mark.asyncio
@patch('wazuh.core.cluster.utils.get_cluster_items')
@patch('wazuh.core.cluster.utils.read_config')
@patch('wazuh.core.cluster.client.asyncio.get_running_loop')
async def test_localclient_send_api_request_ko(mock_get_running_loop, read_config_mock, get_cluster_items_mock):
    """Check the behavior of the send_api_request function for the different types of exceptions that may occur."""

    class Protocol:
        def __init__(self):
            self.response_available = asyncio.Event()

    get_cluster_items_mock.return_value = {
        'intervals': {'worker': {'keep_alive': 1}, 'communication': {'timeout_dapi_request': 2}}
    }

    lc = LocalClient()
    lc.protocol = Protocol()
    lc.protocol.send_request = AsyncMock()
    lc.protocol.send_request.side_effect = [b'None', exception.WazuhClusterError(3018)]
    with patch('asyncio.Event.wait', side_effect=asyncio.TimeoutError):
        with pytest.raises(WazuhInternalError, match=r'.* 3020 .*'):
            await lc.send_api_request(command=b'dapi', data=b'None')
    lc.protocol.send_request.assert_has_calls([call(b'dapi', b'None'), call(b'echo-c', b'keepalive')])


@pytest.mark.asyncio
@patch('wazuh.core.cluster.utils.get_cluster_items')
@patch('wazuh.core.cluster.utils.read_config')
async def test_localclient_execute(read_config_mock, get_cluster_items_mock):
    """Check that the execute function returns the expected value."""

    class Protocol:
        def __init__(self):
            self.on_con_lost = Protocol.testing()

        @staticmethod
        async def testing():
            return 'test'

    with patch('wazuh.core.cluster.local_client.LocalClient.start'):
        with patch('wazuh.core.cluster.local_client.LocalClient.send_api_request', return_value='Test'):
            with patch('asyncio.transports.BaseTransport.close'):
                lc = LocalClient()
                lc.transport = BaseTransport()
                lc.protocol = Protocol()
                assert await lc.execute(command=b'0', data=b'1') == 'Test'


@pytest.mark.asyncio
@patch('wazuh.core.cluster.utils.get_cluster_items')
@patch('wazuh.core.cluster.utils.read_config')
async def test_localclient_send_file(read_config_mock, get_cluster_items_mock):
    """Check that the function send_file returns the value returned by the
    function send_api_request called with the command 'send_file'.
    """
    with patch('wazuh.core.cluster.local_client.LocalClient.start'):
        with patch('wazuh.core.cluster.local_client.LocalClient.send_api_request', return_value=b'wazuh/test python'):
            lc = LocalClient()
            assert await lc.send_file(path='wazuh/test', node_name='python') == b'wazuh/test python'
