# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging
import sys
import time
from unittest.mock import MagicMock, patch, call

import pytest
from freezegun import freeze_time

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        import wazuh.core.cluster.client as client
        from wazuh import WazuhException

from wazuh.core.exception import WazuhClusterError

cluster_items = {'intervals': {'worker': {'keep_alive': 1, 'max_failed_keepalive_attempts': 0, "connection_retry": 2}}}
configuration = {"node_name": "manager", "nodes": [0], "port": 1515}


class FutureMock:
    def __init__(self):
        self.value = True

    def done(self):
        return self.value

    def set_result(self, set):
        pass


class LoopMock:

    def __init__(self):
        pass

    @staticmethod
    async def create_connection(protocol_factory, host, port, ssl):
        return "transport", "protocol"

    def set_exception_handler(self, exc_handler):
        pass

    def create_future(self):
        pass


future_mock = FutureMock()
abstract_client = client.AbstractClient(loop=None, on_con_lost=future_mock, name="name",
                                        logger=None, manager=None, cluster_items=cluster_items)
with patch("asyncio.get_running_loop"):
    abstract_client_manager = client.AbstractClientManager(configuration=configuration, cluster_items=cluster_items,
                                                           performance_test=10, concurrency_test=10, file="/file/path",
                                                           string=1000)


# Test AbstractClientManager methods

def test_acm_init():
    """Check the correct initialization of the AbstractClientManager object."""

    assert abstract_client_manager.name == "manager"
    assert abstract_client_manager.configuration == configuration
    assert abstract_client_manager.cluster_items == cluster_items
    assert abstract_client_manager.performance_test == 10
    assert abstract_client_manager.concurrency_test == 10
    assert abstract_client_manager.file == "/file/path"
    assert abstract_client_manager.string == 1000
    assert abstract_client_manager.logger == logging.getLogger("wazuh")
    assert abstract_client_manager.tag == "Client Manager"
    assert abstract_client_manager.tasks == []
    assert abstract_client_manager.handler_class == client.AbstractClient
    assert abstract_client_manager.client is None
    assert abstract_client_manager.extra_args == {}


def test_acm_add_tasks():
    """Check that the add_tasks function generates an array of tasks based on the parameters of the
    AbstractClientManager object."""

    abstract_client_manager.client = abstract_client
    abstract_client_manager.performance_test = None
    abstract_client_manager.concurrency_test = None
    abstract_client_manager.file = None
    abstract_client_manager.string = None

    # Test simple return
    assert isinstance(abstract_client_manager.add_tasks(), list)
    assert abstract_client_manager.add_tasks() == []

    # Test fourth condition
    abstract_client_manager.string = 1000
    assert isinstance(abstract_client_manager.add_tasks(), list)
    assert abstract_client_manager.add_tasks() == [(abstract_client.send_string_task, (1000,))]

    # Test third condition
    abstract_client_manager.file = "/file/path"
    assert isinstance(abstract_client_manager.add_tasks(), list)
    assert abstract_client_manager.add_tasks() == [(abstract_client.send_file_task, ("/file/path",))]

    # Test second condition
    abstract_client_manager.concurrency_test = 10
    assert isinstance(abstract_client_manager.add_tasks(), list)
    assert abstract_client_manager.add_tasks() == [(abstract_client.concurrency_test_client, (10,))]

    # Test first condition
    abstract_client_manager.performance_test = 10
    assert isinstance(abstract_client_manager.add_tasks(), list)
    assert abstract_client_manager.add_tasks() == [(abstract_client.performance_test_client, (10,))]


@pytest.mark.asyncio
@patch('asyncio.sleep')
@patch('itertools.starmap', return_value="")
@patch('wazuh.core.cluster.client.AbstractClientManager.add_tasks', return_value=[])
async def test_acm_start(add_tasks_mock, starmap_mock, asyncio_sleep_mock):
    """Check that the 'start' method allow a connection to the server and wait until this connection is closed."""

    class ClientMock:
        def __init__(self):
            self.client_echo = ""

    class TransportMock:
        def close(self):
            pass

    async def sleep_mock(connection_retry):
        raise Exception()

    asyncio_sleep_mock.side_effect = sleep_mock

    with patch.object(LoopMock, "create_connection",
                      return_value=(TransportMock(), ClientMock())) as create_connection_mock:
        abstract_client_manager.loop = LoopMock()
        abstract_client_manager.tasks = [(0, 0), (1, 1)]
        abstract_client_manager.configuration |= {
            'cafile': '/test/sslmanager.ca',
            'certfile': '/test/sslmanager.cert',
            'keyfile': '/test/sslmanager.key',
            'keyfile_password': '',
        }

        with patch.object(logging.getLogger("wazuh"), "info") as logger_info_mock, \
            patch.object(logging.getLogger("wazuh"), "error") as logger_error_mock, \
            patch("ssl.create_default_context"):
            # Test the try
            try:
                await abstract_client_manager.start()
            except Exception:
                logger_info_mock.assert_called_with("The connection has been closed. Reconnecting in 10 seconds.")

            # Test the first exception
            create_connection_mock.side_effect = ConnectionRefusedError
            try:
                await abstract_client_manager.start()
            except Exception:
                logger_error_mock.assert_called_with("Could not connect to master. Trying again in 10 seconds.")

            # Test the second exception
            create_connection_mock.side_effect = OSError
            try:
                await abstract_client_manager.start()
            except Exception:
                logger_error_mock.assert_called_with("Could not connect to master: . Trying again in 10 seconds.")
                add_tasks_mock.assert_called_with()
                starmap_mock.assert_called()


# Test AbstractClient methods

def test_ac_init():
    """Check the correct initialization of the AbstractClient object."""

    assert abstract_client.server is None
    assert abstract_client.client_data == b"name"
    assert abstract_client.connected is False
    assert isinstance(abstract_client.on_con_lost, FutureMock)
    assert abstract_client.name == "name"
    assert abstract_client.loop is None


def test_ac_connection_result():
    """Check that once an asyncio.Future object is received, a
       first - connection is established if no problems were found, or
       second - closed if and Exception was received."""

    class CloseMock:
        def close(self):
            pass

    # Check first condition
    with patch.object(logging.getLogger('wazuh'), "error") as logger_mock:
        abstract_client.transport = CloseMock()

        with patch.object(abstract_client.transport, "close") as close_mock:
            # Test when the future is set as a result
            future = asyncio.Future()
            future.set_result([WazuhClusterError(3020)])
            abstract_client.connection_result(future)
            logger_mock.assert_called_once_with(f"Could not connect to master: {str(WazuhClusterError(3020))}.")
            close_mock.assert_called_once()

            logger_mock.reset_mock()
            close_mock.reset_mock()

            # Test when the future is set as an exception
            future = asyncio.Future()
            future.set_exception(WazuhClusterError(3020))
            abstract_client.connection_result(future)
            logger_mock.assert_called_once_with(f"Could not connect to master: {str(WazuhClusterError(3020))}.")
            close_mock.assert_called_once()

    # Check second condition
    with patch.object(logging.getLogger('wazuh'), "info") as logger_mock:
        abstract_client.transport = CloseMock()
        future = asyncio.Future()
        future.set_result(['OK'])
        abstract_client.connection_result(future)
        logger_mock.assert_called_once_with("Successfully connected to master.")
        assert abstract_client.connected is True


@pytest.mark.asyncio
async def test_ac_connection_made():
    """Check that the process of connection to the manager is correctly performed.

        1. asyncio.gather must call send_request(b'hello', self.client_data) coroutine
        2. The done_callback of the future returned by asyncio.gatheris set to
           connection_made inside connection_made
        3. In connection_result function, a message to the log is written
           and abstract_client.connected is set to True

    """

    async def check_connected(abs_cli):
        # coroutine to wait for connected set to True
        while not abs_cli.connected:
            await asyncio.sleep(0.01)

    msg = abstract_client.msg_build(b'return', 1, b'ok')

    with patch.object(abstract_client, 'send_request', return_value=msg) as g_mock:
        with patch.object(abstract_client.logger, 'info') as log_mock:
            abstract_client.connection_made(asyncio.Transport())

            # wait that abstract_client.connected is set to True for 10 seconds
            await asyncio.wait_for(check_connected(abstract_client), 10)
            g_mock.assert_awaited_once_with(command=b'hello', data=abstract_client.client_data)

            # check assertions
            log_mock.assert_called_with("Successfully connected to master.")
            assert abstract_client.connected is True

@patch('wazuh.core.cluster.client.AbstractClient._cancel_all_tasks')
def test_ac_connection_lost(cancel_tasks_mock):
    """Check the behavior when the master closes the connection and when the connection is lost due some problems."""

    future_mock_nested = FutureMock()

    abstract_client.on_con_lost = future_mock_nested

    # Test the first condition
    with patch.object(logging.getLogger('wazuh'), "info") as logger_mock:
        with patch.object(FutureMock, "done", return_value=False) as done_mock:
            with patch.object(FutureMock, "set_result") as set_result_mock:
                abstract_client.connection_lost(exc=None)
                logger_mock.assert_called_once_with('The master closed the connection')
                cancel_tasks_mock.assert_called_once()
                done_mock.assert_called_once()
                set_result_mock.assert_called_once_with(True)

    # Test the second condition
    with patch.object(logging.getLogger('wazuh'), "error") as logger_mock:
        abstract_client.connection_lost(exc=WazuhException(1001))
        logger_mock.assert_called_once_with(f"Connection closed due to an unhandled error: {WazuhException(1001)}\n",
                                            exc_info=False)

def test_ac_cancel_all_tasks():
    """Check whether all tasks and connections are being properly closed."""

    class TaskMock:
        def __init__(self):
            pass

        def cancel(self):
            pass

    class ParentManager:
        def __init__(self, client) -> None:
            self.local_server = self.LocalServer(client)

        class LocalServer:
            def __init__(self, client) -> None:
                self.clients = {"client": client}

    task_mock = TaskMock()
    client_mock = MagicMock()
    mock_manager = ParentManager(client_mock)

    with patch('wazuh.core.cluster.common.Handler.get_manager', return_value=mock_manager):
        with patch('asyncio.all_tasks', return_value=[task_mock]) as all_tasks_mock:
            with patch.object(TaskMock, "cancel") as cancel_mock:
                abstract_client._cancel_all_tasks()
                all_tasks_mock.assert_called_once()
                cancel_mock.assert_called_once()
                client_mock.close.assert_called_once()
                assert mock_manager.local_server.clients == {}

def test_ac_process_response():
    """Check the response the clients receive depending on the input command."""

    # Test the fist condition
    assert (abstract_client.process_response(command=b'ok-m',
                                             payload=b"payload") == b"Successful response from master: " + b"payload")

    # Test the second condition
    with patch('wazuh.core.cluster.common.Handler.process_response', return_value=b'ok') as pr_mock:
        assert abstract_client.process_response(command=b'ok', payload=b"payload") == b'ok'
        pr_mock.assert_called_once_with(b'ok', b"payload")


def test_ac_process_request():
    """Check the command available in clients depending on the input command."""

    # Test the fist condition
    with patch('wazuh.core.cluster.client.AbstractClient.echo_client', return_value=b'ok') as echo_mock:
        assert (abstract_client.process_request(command=b"echo-m", data=b"data") == b'ok')
        echo_mock.assert_called_once_with(b'data')

    # Test the second condition
    with patch('wazuh.core.cluster.common.Handler.process_request', return_value=b'ok') as pr_mock:
        assert abstract_client.process_request(command=b'ok', data=b"data") == b'ok'
        pr_mock.assert_called_once_with(b'ok', b"data")


def test_ac_echo_client():
    """Check the proper output of the 'echo_client' method."""

    assert abstract_client.echo_client(b"data") == (b'ok-c', b"data")


@pytest.mark.asyncio
@patch('asyncio.sleep')
@patch.object(FutureMock, "done", return_value=False)
@patch('wazuh.core.cluster.client.AbstractClient.send_request', return_value=b"ok")
async def test_ac_client_echo_ok(send_request_mock, done_mock, asyncio_sleep_mock):
    """Test if a keepalive is being send to the server every couple of seconds until the connection is lost."""

    class TransportMock:

        def __init__(self):
            pass

        def close(self):
            pass

    async def sleep_mock(connection_retry):
        raise Exception()

    def set_assignment():
        time.sleep(0.4)
        done_mock.return_value = True

    abstract_client.connected = True
    asyncio_sleep_mock.side_effect = sleep_mock

    # Test try
    with patch.object(logging.getLogger("wazuh"), "info") as logger_mock:
        with patch('wazuh.core.cluster.common.Handler.setup_task_logger',
                   return_value=logging.getLogger("wazuh")) as setup_logger_mock:
            try:
                await abstract_client.client_echo()
            except Exception:
                send_request_mock.assert_called_once_with(b'echo-c', b'keepalive')
                setup_logger_mock.assert_called_once_with("Keep Alive")
                logger_mock.assert_called_with("ok")

    # Test except
    with patch.object(logging.getLogger("wazuh"), "error") as logger_mock:
        with patch('wazuh.core.cluster.common.Handler.setup_task_logger',
                   return_value=logging.getLogger("wazuh")) as setup_logger_mock:
            with patch.object(TransportMock, "close") as close_mock:
                abstract_client.transport = TransportMock()
                done_mock.return_value = False
                send_request_mock.side_effect = Exception()
                try:
                    await abstract_client.client_echo()
                except Exception:
                    setup_logger_mock.assert_called_once_with("Keep Alive")
                    close_mock.assert_called_once()
                    logger_mock.assert_any_call("Error sending keep alive: ")
                    logger_mock.assert_called_with("Maximum number of failed keep alives reached. Disconnecting.")


@pytest.mark.asyncio
@freeze_time("2022-01-01")
@patch.object(FutureMock, "done", return_value=False)
@patch('wazuh.core.cluster.client.perf_counter', return_value=0)
@patch('wazuh.core.cluster.client.AbstractClient.send_request', return_value="ok")
async def test_ac_performance_test_client(send_request_mock, perf_counter_mock, done_mock):
    """Test is the master replies with aa payload of the same length as the one that was sent."""

    async def asyncio_sleep_mock(delay, result=None, *, loop=None):
        assert delay == 3
        raise Exception()

    with patch('asyncio.sleep', asyncio_sleep_mock):
        with patch.object(logging.getLogger("wazuh"), "error") as logger_mock:
            try:
                await asyncio.create_task(abstract_client.performance_test_client(10))
            except Exception:
                pass

            logger_mock.assert_called_with("ok", exc_info=False)
            send_request_mock.assert_called_with(b'echo', b'a' * 10)

        with patch.object(logging.getLogger("wazuh"), "info") as logger_mock:
            done_mock.return_value = False
            try:
                await asyncio.create_task(abstract_client.performance_test_client(2))
            except Exception:
                pass
            logger_mock.assert_called_with(f"Received size: {2} // Time: {0}")
            send_request_mock.assert_called_with(b'echo', b'a' * 2)

        done_mock.assert_any_call()


@pytest.mark.asyncio
@freeze_time("2022-01-01")
@patch.object(FutureMock, "done", return_value=False)
@patch('wazuh.core.cluster.client.perf_counter', return_value=0)
@patch('wazuh.core.cluster.client.AbstractClient.send_request', return_value="ok")
async def test_ac_concurrency_test_client(send_request_mock, perf_counter_mock, done_mock):
    """Check how the server reply to all requests until the connection is lost."""

    n_msgs = 5

    async def asyncio_sleep_mock(delay, result=None, *, loop=None):
        assert delay == 3
        raise Exception()

    with patch('asyncio.sleep', asyncio_sleep_mock):
        with patch.object(logging.getLogger("wazuh"), "info") as logger_mock:
            try:
                await asyncio.create_task(abstract_client.concurrency_test_client(n_msgs))
            except Exception:
                pass

            done_mock.assert_any_call()
            for i in range(n_msgs):
                send_request_mock.assert_has_calls([call(b'echo', f'concurrency {i}'.encode())], any_order=True)
            logger_mock.assert_called_with(f"Time sending {n_msgs} messages: {0}")


@pytest.mark.asyncio
@freeze_time("2022-01-01")
@patch('wazuh.core.cluster.client.perf_counter', return_value=0)
@patch('wazuh.core.cluster.client.AbstractClient.send_file', return_value="ok")
async def test_ac_send_file_task(send_file_mock, perf_counter_mock):
    """Test the 'send_file' protocol."""

    with patch.object(logging.getLogger("wazuh"), "debug") as logger_mock:
        await abstract_client.send_file_task("filename")
        send_file_mock.assert_called_once_with("filename")
        logger_mock.assert_any_call("ok")
        logger_mock.assert_called_with(f"Time: {0}")


@pytest.mark.asyncio
@freeze_time("2022-01-01")
@patch('wazuh.core.cluster.client.perf_counter', return_value=0)
@patch('wazuh.core.cluster.client.AbstractClient.send_string', return_value="ok")
async def test_ac_send_string_task(send_string_mock, perf_counter_mock):
    """Test the 'send_string' protocol."""

    with patch.object(logging.getLogger("wazuh"), "debug") as logger_mock:
        await abstract_client.send_string_task(10)
        send_string_mock.assert_called_once_with(my_str=b'a' * 10)
        logger_mock.assert_any_call("ok")
        logger_mock.assert_called_with(f"Time: {0}")
