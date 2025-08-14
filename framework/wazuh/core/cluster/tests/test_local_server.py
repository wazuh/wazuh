# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import logging
import sys
import asyncio
from contextvars import ContextVar
from unittest.mock import AsyncMock, MagicMock
from unittest.mock import patch

import pytest
from uvloop import Loop

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.core.cluster.local_server import *
        from wazuh.core.cluster.dapi import dapi
        from wazuh.core.exception import WazuhClusterError

async def wait_function_called(func_mock):
    while not func_mock.call_count:
        await asyncio.sleep(0.01)

@pytest.mark.asyncio
async def test_LocalServerHandler_connection_made(event_loop):
    """Check that the process for accepting a connection is correctly defined."""

    class ServerMock:
        def __init__(self):
            self.clients = {}

    transport = "testing"
    logger = logging.getLogger("connection_made")
    with patch.object(logger, "debug") as logger_debug_mock:
        with patch("wazuh.core.cluster.local_server.context_tag", ContextVar("tag", default="")) as mock_contextvar:
            lsh = LocalServerHandler(server=ServerMock(), loop=event_loop, fernet_key=None, cluster_items={}, logger=logger)
            lsh.connection_made(transport=transport)
            assert isinstance(lsh.name, str)
            assert lsh.transport == transport
            assert lsh.server.clients == {lsh.name: lsh}
            assert lsh.tag == f"Local {lsh.name}"
            assert mock_contextvar.get() == lsh.tag

            logger_debug_mock.assert_called_once_with("Connection received in local server.")


@pytest.mark.asyncio
@patch("wazuh.core.cluster.local_server.server.AbstractServerHandler.process_request")
async def test_LocalServerHandler_process_request(process_request_mock, event_loop):
    """Check the functions that are executed according to the command received."""
    lsh = LocalServerHandler(server=None, loop=event_loop, fernet_key=None, cluster_items={})
    with patch.object(lsh, "get_config") as get_config_mock:
        lsh.process_request(command=b"get_config", data=b"test")
        get_config_mock.assert_called_once()

    with patch.object(lsh, "get_nodes") as get_nodes_mock:
        lsh.process_request(command=b"get_nodes", data=b"test")
        get_nodes_mock.assert_called_once()

    with patch.object(lsh, "get_health") as get_health_mock:
        lsh.process_request(command=b"get_health", data=b"test")
        get_health_mock.assert_called_once()

    with patch.object(lsh, "send_file_request") as send_file_mock:
        lsh.process_request(command=b"send_file", data=b"test send_file")
        send_file_mock.assert_called_with("test", "send_file")

    lsh.process_request(command=b"process_request", data=b"test process_request")
    process_request_mock.assert_called_with(b"process_request", b"test process_request")


@pytest.mark.asyncio
async def test_LocalServerHandler_get_config(event_loop):
    """Set the behavior of the get_config function."""

    class ServerMock:
        def __init__(self):
            self.configuration = {"test": "get_config"}

    lsh = LocalServerHandler(server=ServerMock(), loop=event_loop, fernet_key=None, cluster_items={})
    assert lsh.get_config() == (b"ok", b'{"test": "get_config"}')


@pytest.mark.asyncio
async def test_LocalServerHandler_get_node(event_loop):
    """Set the behavior of the get_node function."""

    class NodeMock:
        def get_node(self):
            pass

    class ServerMock:
        def __init__(self):
            self.node = NodeMock()

    server_mock = ServerMock()
    lsh = LocalServerHandler(server=server_mock, loop=event_loop, fernet_key=None, cluster_items={})
    with patch.object(server_mock.node, "get_node", return_value="test_get_node"):
        assert lsh.get_node() == "test_get_node"


@pytest.mark.asyncio
async def test_LocalServerHandler_get_nodes(event_loop):
    """Set the behavior of the get_nodes function."""
    lsh = LocalServerHandler(server=None, loop=event_loop, fernet_key=None, cluster_items={})
    with pytest.raises(NotImplementedError):
        lsh.get_nodes(filter_nodes=b"a")


@pytest.mark.asyncio
async def test_LocalServerHandler_get_health(event_loop):
    """Set the behavior of the get_health function."""
    lsh = LocalServerHandler(server=None, loop=event_loop, fernet_key=None, cluster_items={})
    with pytest.raises(NotImplementedError):
        lsh.get_health(filter_nodes=b"a")


@pytest.mark.asyncio
async def test_LocalServerHandler_get_ruleset_hashes(event_loop):
    """Set the behavior of the get_ruleset_hashes function."""
    class ServerMock:
        def __init__(self):
            self.node = MagicMock()

    lsh = LocalServerHandler(server=ServerMock(), loop=event_loop, fernet_key=None, cluster_items={})
    with patch("wazuh.core.cluster.local_server.cluster.get_ruleset_status",
               return_value={'test_path': 'hash'}) as get_ruleset_status_mock:
        assert lsh.get_ruleset_hashes() == (b'ok', json.dumps({'test_path': 'hash'}).encode())
        get_ruleset_status_mock.assert_called_once()


@pytest.mark.asyncio
async def test_LocalServerHandler_send_file_request(event_loop):
    """Set the behavior of the send_file_request function."""
    lsh = LocalServerHandler(server=None, loop=event_loop, fernet_key=None, cluster_items={})
    with pytest.raises(NotImplementedError):
        lsh.send_file_request(path="a", node_name="b")


@pytest.mark.asyncio
@patch("wazuh.core.cluster.local_server.LocalServerHandler.send_request", return_value='changed')
async def test_LocalServerHandler_get_send_file_response(send_request_mock:AsyncMock, event_loop: Loop):
    """Check that send_file response is sent to the API."""

    def callback_mock(future: asyncio.Future):
        assert future.result() == 'anydata'

    async def wait_callback_called(callback_mock):
        while not callback_mock.call_count:
            await asyncio.sleep(0.01)

    future = asyncio.Future(loop=event_loop)
    future.set_result('test_get_send_file_response')
    lsh = LocalServerHandler(server=None, loop=event_loop, fernet_key=None, cluster_items={})
    with patch.object(lsh, 'send_res_callback', side_effect=callback_mock) as send_res_callback_mock:
        lsh.get_send_file_response(future=future)
        await wait_callback_called(send_res_callback_mock)
        send_request_mock.assert_awaited_once_with(command=b"send_f_res", data="test_get_send_file_response")
        send_res_callback_mock.assert_called_once() 


@pytest.mark.asyncio
async def test_LocalServerHandler_send_res_callback(event_loop):
    """Check that any future exceptions created are sent to the logger."""

    def cancelled_mock():
        return False

    exc = Exception('Testing')
    future = asyncio.Future()
    with patch.object(future, "cancelled", cancelled_mock):
        with patch.object(future, "exception", return_value=exc):
            logger = logging.getLogger("connection_made")
            with patch.object(logger, "error") as logger_error_mock:
                lsh = LocalServerHandler(server=None, loop=event_loop, fernet_key=None, cluster_items={},
                                         logger=logger)
                lsh.send_res_callback(future=future)

                logger_error_mock.assert_called_once_with(exc, exc_info=False)


@pytest.mark.asyncio
async def test_LocalServer_init(event_loop):
    """Check and set the behaviour of the LocalServer's constructor."""

    class NodeMock:
        def __init__(self):
            self.local_server = None

    node = NodeMock()

    with patch("asyncio.get_running_loop", return_value=event_loop):
        ls = LocalServer(node=node, performance_test=0, concurrency_test=0,
                        configuration={}, cluster_items={}, enable_ssl=True)
        assert ls.node == node
        assert ls.node.local_server == ls
        assert ls.handler_class == LocalServerHandler


@pytest.mark.asyncio
@patch("asyncio.gather", side_effect=AsyncMock())
@patch("os.path.join", return_value="test_path")
async def test_LocalServer_start(join_mock, gather_mock, event_loop):
    """Check that the server (LocalServer) and the necessary asynchronous tasks are correctly started."""

    class SocketMock:
        def getsockname(self):
            return "socket_test"

    class LocalServerMock:
        def __init__(self):
            self.sockets = [SocketMock(), "1"]
            self.serve_forever = SocketMock

        async def __aenter__(self):
            pass

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    class NodeMock:
        def __init__(self):
            self.local_server = None

    async def create_unix_server_mock(protocol_factory, path):
        return LocalServerMock()

    def handler_class_mock(server=None, loop=None, fernet_key='', logger=None, cluster_items={}):
        pass

    logger = logging.getLogger("connection_made")
    with patch.object(logger, "error") as logger_error_mock:
        ls = LocalServer(node=NodeMock(), performance_test=0, concurrency_test=0,
                         configuration={}, cluster_items={}, enable_ssl=True, logger=logger)

    with patch.object(ls, "handler_class", handler_class_mock):
        with patch.object(event_loop, "create_unix_server", create_unix_server_mock):
            with pytest.raises(KeyboardInterrupt):
                await ls.start()
                logger_error_mock.assert_called_once_with(
                    "Could not create server: [Errno 2] No such file or directory: 'test_path'")

            with patch.object(logger, "info") as logger_info_mock:
                with patch("os.chmod"):
                    ls.tasks = []
                    await ls.start()
                    logger_info_mock.assert_called_once_with("Serving on socket_test")
                    assert ls.tasks == [SocketMock]


@pytest.mark.asyncio
@patch("wazuh.core.cluster.local_server.server.AbstractServerHandler.process_request")
async def test_LocalServerHandlerMaster_process_request(process_request_mock, event_loop):
    """Check that all available responses are defined on the local master server."""

    class ClientMock:
        async def send_request(self, request):
            pass

    class DAPIMock:
        def add_request(self, request):
            pass

    class NodeMock:
        def __init__(self):
            self.clients = {"dapi": ClientMock}

    class ServerMock:
        def __init__(self):
            self.dapi = DAPIMock()
            self.node = NodeMock()

    server_mock = ServerMock()
    lshm = LocalServerHandlerMaster(server=server_mock, loop=event_loop, fernet_key=None, cluster_items={})

    with patch("wazuh.core.cluster.local_server.context_tag", ContextVar("tag", default="")) as mock_contextvar:
        lshm.name = "test1"
        lshm.process_request(command=b"hello", data=b"bye")
        assert mock_contextvar.get() == f"Local {lshm.name}"
        process_request_mock.assert_called_with(b"hello", b"bye")

    with patch.object(server_mock.dapi, "add_request") as add_request_mock:
        assert lshm.process_request(command=b"dapi", data=b"bye") == (b"ok", b"Added request to API requests queue")
        add_request_mock.assert_called_once_with(b"test1 bye")

    with patch.object(server_mock.node.clients["dapi"], "send_request") as send_request_mock:
        assert lshm.process_request(command=b"dapi_fwd", data=b"dapi fwd") == (
            b"ok", b"Request forwarded to worker node")
        send_request_mock.assert_called_once_with(b"dapi", b"test1 fwd")

    with pytest.raises(WazuhClusterError, match=".* 3022 .*"):
        lshm.process_request(command=b"dapi_fwd", data=b"no fwd")


@pytest.mark.asyncio
async def test_LocalServerHandlerMaster_get_nodes(event_loop):
    """Set the behavior of the get_nodes function of the LocalServerHandlerMaster class."""

    class NodeMock:
        def get_connected_nodes(self, test):
            return {"get_node": test}

    class ServerMock:
        def __init__(self):
            self.node = NodeMock()

    lshm = LocalServerHandlerMaster(server=ServerMock(), loop=event_loop, fernet_key=None, cluster_items={})
    assert lshm.get_nodes(arguments=b"{\"test\": \"a\"}") == (b'ok', b'{"get_node": "a"}')


@pytest.mark.asyncio
async def test_LocalServerHandlerMaster_get_health(event_loop):
    """Set the behavior of the get_health function of the LocalServerHandlerMaster class."""

    class NodeMock:
        def get_health(self, test):
            return {"get_health": test}

    class ServerMock:
        def __init__(self):
            self.node = NodeMock()

    lshm = LocalServerHandlerMaster(server=ServerMock(), loop=event_loop, fernet_key=None, cluster_items={})
    assert lshm.get_health(filter_nodes=b"{\"get_health\": \"a\"}") == (b'ok', b'{"get_health": {"get_health": "a"}}')


@pytest.mark.asyncio
async def test_LocalServerHandlerMaster_send_file_request(event_loop):
    """Check that the task for sending files is created."""

    class ClientMock:
        async def send_file(self, path):
            return "send_testing"

    class NodeMock:
        def __init__(self):
            self.clients = {"dapi": ClientMock}

    class ServerMock:
        def __init__(self):
            self.node = NodeMock()

    async def wait_callback_called(callback_mock):
        while not callback_mock.call_count:
            await asyncio.sleep(0.01)

    def callback_mock(future: asyncio.Future):
        assert future.result() == 'send_file_return_value'
        
    server_mock = ServerMock()
    lshm = LocalServerHandlerMaster(server=server_mock, loop=event_loop, fernet_key=None, cluster_items={})
    with pytest.raises(WazuhClusterError, match=".* 3022 .*"):
        lshm.send_file_request(path="/tmp", node_name="no exists")

    with patch.object(server_mock.node.clients["dapi"], "send_file", return_value = 'send_file_return_value') as send_file_mock:
        with patch.object(lshm, 'get_send_file_response', side_effect=callback_mock) as get_send_file_response_callback_mock:
            assert lshm.send_file_request(path="/tmp", node_name="dapi") == \
                    (b'ok', b'Forwarding file to master node')
            await wait_callback_called(get_send_file_response_callback_mock)
            await wait_callback_called(send_file_mock)
            send_file_mock.assert_awaited_with("/tmp")
            

@pytest.mark.asyncio
async def test_LocalServerMaster_init(event_loop):
    """Check and set the behaviour of the LocalServerMaster's constructor."""

    class NodeMock:
        def __init__(self):
            self.local_server = None

    node = NodeMock()
    with patch("asyncio.get_running_loop", return_value=event_loop):
        lsm = LocalServerMaster(node=node, performance_test=0, concurrency_test=0,
                                configuration={}, cluster_items={}, enable_ssl=True)
        assert lsm.handler_class == LocalServerHandlerMaster
        assert isinstance(lsm.dapi, dapi.APIRequestQueue)
        assert isinstance(lsm.sendsync, dapi.SendSyncRequestQueue)


@pytest.mark.asyncio
@patch("wazuh.core.cluster.local_server.LocalServerHandler.process_request")
async def test_LocalServerHandlerWorker_process_request(process_request_mock, event_loop):
    """Check that all available responses are defined on the local worker server."""

    class LoggerMock:
        def debug2(self, msg):
            pass

    class ClientMock:
        async def send_request(self, request):
            pass

    class NodeMock:
        def __init__(self):
            self.client = None

    class ServerMock:
        def __init__(self):
            self.node = NodeMock()

    logger = LoggerMock()
    server_mock = ServerMock()
    lshw = LocalServerHandlerWorker(server=server_mock, loop=event_loop, fernet_key=None, cluster_items={}, logger=logger)

    with patch("wazuh.core.cluster.local_server.context_tag", ContextVar("tag", default="")) as mock_contextvar:
        lshw.name = "test1"
        lshw.process_request(command=b"hello", data=b"bye")
        assert mock_contextvar.get() == f"Local {lshw.name}"
        process_request_mock.assert_called_with(b"hello", b"bye")

    with pytest.raises(WazuhClusterError, match=".* 3023 .*"):
        lshw.process_request(command=b"dapi", data=b"bye")

    with pytest.raises(WazuhClusterError, match=".* 3023 .*"):
        lshw.process_request(command=b"sendsync", data=b"bye")

    with pytest.raises(WazuhClusterError, match=".* 3023 .*"):
        lshw.process_request(command=b"sendasync", data=b"bye")

    with pytest.raises(WazuhClusterError, match=".* 3023 .*"):
        lshw.process_request(command=b"sendrreload", data=b"bye")

    server_mock.node.client = ClientMock()
    with patch.object(server_mock.node.client, "send_request", return_value='') as send_request_mock:
        results = lshw.process_request(command=b"dapi", data=b"bye")
        assert results == (b"ok", b"Added request to API requests queue")
        await asyncio.sleep(0.1)
        send_request_mock.assert_awaited_once_with(b"dapi", b"test1 bye")
        send_request_mock.reset_mock()

        results = lshw.process_request(command=b"sendsync", data=b"bye")
        assert results == (None, None)
        await asyncio.sleep(0.1)
        send_request_mock.assert_awaited_once_with(b"sendsync", b"test1 bye")
        send_request_mock.reset_mock()

        results = lshw.process_request(command=b"sendasync", data=b"bye")
        assert results == (b"ok", b"Added request to sendsync requests queue")        
        await asyncio.sleep(0.1)
        send_request_mock.assert_awaited_once_with(b"sendsync", b"test1 bye")


@pytest.mark.asyncio
async def test_LocalServerHandlerWorker_set_reload_ruleset_flag(event_loop):
    """Test that set_reload_ruleset_flag acquires the lock and sets the flag."""
    class ReloadFlagMock:
        def __init__(self):
            self.lock_acquired = False
            self.set_called = False
        async def __aenter__(self):
            self.lock_acquired = True
            return self
        async def __aexit__(self, exc_type, exc, tb):
            self.lock_acquired = False
        def set(self):
            self.set_called = True

    class ClientMock:
        def __init__(self):
            self.reload_ruleset_flag = ReloadFlagMock()

    class NodeMock:
        def __init__(self):
            self.client = ClientMock()

    class ServerMock:
        def __init__(self):
            self.node = NodeMock()

    lshw = LocalServerHandlerWorker(server=ServerMock(), loop=event_loop, fernet_key=None, cluster_items={})

    await lshw.set_reload_ruleset_flag()
    reload_flag = lshw.server.node.client.reload_ruleset_flag
    assert reload_flag.lock_acquired is False  # Should be released after context
    assert reload_flag.set_called is True


@pytest.mark.asyncio
async def test_AsyncReloadRulesetFlag_initial_state():
    """Test AsyncReloadRulesetFlag initial state is not set."""
    from wazuh.core.cluster.worker import AsyncReloadRulesetFlag
    flag = AsyncReloadRulesetFlag()
    assert not flag.is_set()

@pytest.mark.asyncio
async def test_AsyncReloadRulesetFlag_set():
    """Test AsyncReloadRulesetFlag set() method."""
    from wazuh.core.cluster.worker import AsyncReloadRulesetFlag
    flag = AsyncReloadRulesetFlag()
    flag.set()
    assert flag.is_set()

@pytest.mark.asyncio
async def test_AsyncReloadRulesetFlag_clear():
    """Test AsyncReloadRulesetFlag clear() method."""
    from wazuh.core.cluster.worker import AsyncReloadRulesetFlag
    flag = AsyncReloadRulesetFlag()
    flag.set()
    flag.clear()
    assert not flag.is_set()

@pytest.mark.asyncio
async def test_AsyncReloadRulesetFlag_async_context_manager():
    """Test AsyncReloadRulesetFlag async context manager acquires and releases lock."""
    from wazuh.core.cluster.worker import AsyncReloadRulesetFlag
    flag = AsyncReloadRulesetFlag()
    async with flag as ctx:
        assert ctx is flag
        flag.set()
        assert flag.is_set()
    # After context, flag should still be set (lock is released, not flag)
    assert flag.is_set()

