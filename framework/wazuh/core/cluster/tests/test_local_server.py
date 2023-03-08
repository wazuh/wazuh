# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import logging
import sys
from contextvars import ContextVar
from unittest.mock import AsyncMock, MagicMock
from unittest.mock import patch

import pytest
from uvloop import EventLoopPolicy, new_event_loop

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

asyncio.set_event_loop_policy(EventLoopPolicy())
loop = new_event_loop()


def test_LocalServerHandler_connection_made():
    """Check that the process for accepting a connection is correctly defined."""

    class ServerMock:
        def __init__(self):
            self.clients = {}

    transport = "testing"
    logger = logging.getLogger("connection_made")
    with patch.object(logger, "debug") as logger_debug_mock:
        with patch("wazuh.core.cluster.local_server.context_tag", ContextVar("tag", default="")) as mock_contextvar:
            lsh = LocalServerHandler(server=ServerMock(), loop=loop, fernet_key=None, cluster_items={}, logger=logger)
            lsh.connection_made(transport=transport)
            assert isinstance(lsh.name, str)
            assert lsh.transport == transport
            assert lsh.server.clients == {lsh.name: lsh}
            assert lsh.tag == f"Local {lsh.name}"
            assert mock_contextvar.get() == lsh.tag

            logger_debug_mock.assert_called_once_with("Connection received in local server.")


@patch("wazuh.core.cluster.local_server.server.AbstractServerHandler.process_request")
def test_LocalServerHandler_process_request(process_request_mock):
    """Check the functions that are executed according to the command received."""
    lsh = LocalServerHandler(server=None, loop=loop, fernet_key=None, cluster_items={})
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


def test_LocalServerHandler_get_config():
    """Set the behavior of the get_config function."""

    class ServerMock:
        def __init__(self):
            self.configuration = {"test": "get_config"}

    lsh = LocalServerHandler(server=ServerMock(), loop=loop, fernet_key=None, cluster_items={})
    assert lsh.get_config() == (b"ok", b'{"test": "get_config"}')


def test_LocalServerHandler_get_node():
    """Set the behavior of the get_node function."""

    class NodeMock:
        def get_node(self):
            pass

    class ServerMock:
        def __init__(self):
            self.node = NodeMock()

    server_mock = ServerMock()
    lsh = LocalServerHandler(server=server_mock, loop=loop, fernet_key=None, cluster_items={})
    with patch.object(server_mock.node, "get_node", return_value="test_get_node"):
        assert lsh.get_node() == "test_get_node"


def test_LocalServerHandler_get_nodes():
    """Set the behavior of the get_nodes function."""
    lsh = LocalServerHandler(server=None, loop=loop, fernet_key=None, cluster_items={})
    with pytest.raises(NotImplementedError):
        lsh.get_nodes(filter_nodes=b"a")


def test_LocalServerHandler_get_health():
    """Set the behavior of the get_health function."""
    lsh = LocalServerHandler(server=None, loop=loop, fernet_key=None, cluster_items={})
    with pytest.raises(NotImplementedError):
        lsh.get_health(filter_nodes=b"a")


def test_LocalServerHandler_get_ruleset_hashes():
    """Set the behavior of the get_ruleset_hashes function."""
    class ServerMock:
        def __init__(self):
            self.node = MagicMock()

    lsh = LocalServerHandler(server=ServerMock(), loop=loop, fernet_key=None, cluster_items={})
    with patch("wazuh.core.cluster.local_server.cluster.get_ruleset_status",
               return_value={'test_path': 'hash'}) as get_ruleset_status_mock:
        assert lsh.get_ruleset_hashes() == (b'ok', json.dumps({'test_path': 'hash'}).encode())
        get_ruleset_status_mock.assert_called_once()


def test_LocalServerHandler_send_file_request():
    """Set the behavior of the send_file_request function."""
    lsh = LocalServerHandler(server=None, loop=loop, fernet_key=None, cluster_items={})
    with pytest.raises(NotImplementedError):
        lsh.send_file_request(path="a", node_name="b")


def test_LocalServerHandler_get_send_file_response():
    """Check that send_file response is sent to the API."""

    def result_mock():
        return "test_get_send_file_response"

    async def func_mock():
        pass

    future = asyncio.Future()
    task = asyncio.Task(func_mock())
    with patch.object(task, "add_done_callback") as add_done_callback_mock:
        with patch("wazuh.core.cluster.local_server.asyncio.create_task",
                   return_value=task) as create_task_mock:
            with patch("wazuh.core.cluster.local_server.LocalServerHandler.send_request") as send_request_mock:
                lsh = LocalServerHandler(server=None, loop=loop, fernet_key=None, cluster_items={})
                lsh.send_res_callback = "changed"
                with patch.object(future, "result", result_mock):
                    lsh.get_send_file_response(future=future)
                    send_request_mock.assert_called_with(command=b"send_f_res", data="test_get_send_file_response")
                    create_task_mock.assert_called_once()
                    add_done_callback_mock.assert_called_with("changed")


def test_LocalServerHandler_send_res_callback():
    """Check that any future exceptions created are sent to the logger."""

    def cancelled_mock():
        return False

    def exception_mock():
        return "testing"

    future = asyncio.Future()
    with patch.object(future, "cancelled", cancelled_mock):
        with patch.object(future, "exception", exception_mock):
            logger = logging.getLogger("connection_made")
            with patch.object(logger, "error") as logger_error_mock:
                lsh = LocalServerHandler(server=None, loop=loop, fernet_key=None, cluster_items={},
                                         logger=logger)
                lsh.send_res_callback(future=future)
                logger_error_mock.assert_called_once_with("testing", exc_info=False)


@patch("asyncio.get_running_loop", return_value=loop)
def test_LocalServer_init(loop_mock):
    """Check and set the behaviour of the LocalServer's constructor."""

    class NodeMock:
        def __init__(self):
            self.local_server = None

    node = NodeMock()
    ls = LocalServer(node=node, performance_test=0, concurrency_test=0,
                     configuration={}, cluster_items={}, enable_ssl=True)
    assert ls.node == node
    assert ls.node.local_server == ls
    assert ls.handler_class == LocalServerHandler


@pytest.mark.asyncio
@patch("asyncio.gather", side_effect=AsyncMock())
@patch("os.path.join", return_value="test_path")
@patch("uvloop.EventLoopPolicy")
@patch("asyncio.set_event_loop_policy")
@patch("asyncio.get_running_loop", return_value=loop)
async def test_LocalServer_start(loop_mock, set_event_loop_mock, eventlooppolicy_mock, join_mock, gather_mock):
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
        with patch.object(loop, "create_unix_server", create_unix_server_mock):
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


@patch("asyncio.create_task")
@patch("wazuh.core.cluster.local_server.server.AbstractServerHandler.process_request")
@patch("asyncio.get_running_loop", return_value=loop)
def test_LocalServerHandlerMaster_process_request(loop_mock, process_request_mock, create_task_mock):
    """Check that all available responses are defined on the local master server."""

    class ClientMock:
        def send_request(self, request):
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
    lshm = LocalServerHandlerMaster(server=server_mock, loop=loop, fernet_key=None, cluster_items={})

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


def test_LocalServerHandlerMaster_get_nodes():
    """Set the behavior of the get_nodes function of the LocalServerHandlerMaster class."""

    class NodeMock:
        def get_connected_nodes(self, test):
            return {"get_node": test}

    class ServerMock:
        def __init__(self):
            self.node = NodeMock()

    lshm = LocalServerHandlerMaster(server=ServerMock(), loop=loop, fernet_key=None, cluster_items={})
    assert lshm.get_nodes(arguments=b"{\"test\": \"a\"}") == (b'ok', b'{"get_node": "a"}')


def test_LocalServerHandlerMaster_get_health():
    """Set the behavior of the get_health function of the LocalServerHandlerMaster class."""

    class NodeMock:
        def get_health(self, test):
            return {"get_health": test}

    class ServerMock:
        def __init__(self):
            self.node = NodeMock()

    lshm = LocalServerHandlerMaster(server=ServerMock(), loop=loop, fernet_key=None, cluster_items={})
    assert lshm.get_health(filter_nodes=b"{\"get_health\": \"a\"}") == (b'ok', b'{"get_health": {"get_health": "a"}}')


def test_LocalServerHandlerMaster_send_file_request():
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

    async def func_mock():
        pass

    server_mock = ServerMock()
    lshm = LocalServerHandlerMaster(server=server_mock, loop=loop, fernet_key=None, cluster_items={})
    with pytest.raises(WazuhClusterError, match=".* 3022 .*"):
        lshm.send_file_request(path="/tmp", node_name="no exists")

    task = asyncio.Task(func_mock())
    with patch.object(task, "add_done_callback") as add_done_callback_mock:
        with patch("wazuh.core.cluster.local_server.asyncio.create_task",
                   return_value=task) as create_task_mock:
            with patch.object(server_mock.node.clients["dapi"], "send_file") as send_file_mock:
                assert lshm.send_file_request(path="/tmp", node_name="dapi") == \
                       (b'ok', b'Forwarding file to master node')
                send_file_mock.assert_called_with("/tmp")
                create_task_mock.assert_called_once()
                add_done_callback_mock.assert_called_once()


@patch("asyncio.get_running_loop", return_value=loop)
def test_LocalServerMaster_init(loop_mock):
    """Check and set the behaviour of the LocalServerMaster's constructor."""

    class NodeMock:
        def __init__(self):
            self.local_server = None

    node = NodeMock()
    lsm = LocalServerMaster(node=node, performance_test=0, concurrency_test=0,
                            configuration={}, cluster_items={}, enable_ssl=True)
    assert lsm.handler_class == LocalServerHandlerMaster
    assert isinstance(lsm.dapi, dapi.APIRequestQueue)
    assert isinstance(lsm.sendsync, dapi.SendSyncRequestQueue)


@patch("asyncio.create_task")
@patch("wazuh.core.cluster.local_server.LocalServerHandler.process_request")
@patch("asyncio.get_running_loop", return_value=loop)
def test_LocalServerHandlerWorker_process_request(loop_mock, process_request_mock, create_task_mock):
    """Check that all available responses are defined on the local worker server."""

    class LoggerMock:
        def debug2(self, msg):
            pass

    class ClientMock:
        def send_request(self, request):
            pass

    class NodeMock:
        def __init__(self):
            self.client = None

    class ServerMock:
        def __init__(self):
            self.node = NodeMock()

    logger = LoggerMock()
    server_mock = ServerMock()
    lshw = LocalServerHandlerWorker(server=server_mock, loop=loop, fernet_key=None, cluster_items={}, logger=logger)

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

    server_mock.node.client = ClientMock()
    with patch.object(server_mock.node.client, "send_request") as send_request_mock:
        assert lshw.process_request(command=b"dapi", data=b"bye") == (b"ok", b"Added request to API requests queue")
        send_request_mock.assert_called_once_with(b"dapi", b"test1 bye")
        create_task_mock.assert_called_once()
        create_task_mock.reset_mock()
        send_request_mock.reset_mock()

        assert lshw.process_request(command=b"sendsync", data=b"bye") == (None, None)
        send_request_mock.assert_called_once_with(b"sendsync", b"test1 bye")
        create_task_mock.assert_called_once()
        create_task_mock.reset_mock()
        send_request_mock.reset_mock()

        assert lshw.process_request(command=b"sendasync", data=b"bye") == \
               (b"ok", b"Added request to sendsync requests queue")
        send_request_mock.assert_called_once_with(b"sendsync", b"test1 bye")
        create_task_mock.assert_called_once()
        create_task_mock.reset_mock()
        send_request_mock.reset_mock()


def test_LocalServerHandlerWorker_get_nodes():
    """Set the behavior of the get_nodes function of the LocalServerHandlerWorker class."""
    lshw = LocalServerHandlerWorker(server=None, loop=loop, fernet_key=None, cluster_items={})
    with patch.object(lshw, "send_request_to_master") as send_request_to_master_mock:
        lshw.get_nodes(arguments=b"test_worker_get_nodes")
        send_request_to_master_mock.assert_called_once_with(b"get_nodes", b"test_worker_get_nodes")


def test_LocalServerHandlerWorker_get_health():
    """Set the behavior of the get_health function of the LocalServerHandlerWorker class."""
    lshw = LocalServerHandlerWorker(server=None, loop=loop, fernet_key=None, cluster_items={})
    with patch.object(lshw, "send_request_to_master") as send_request_to_master_mock:
        lshw.get_health(filter_nodes=b"test_worker_get_health")
        send_request_to_master_mock.assert_called_once_with(b"get_health", b"test_worker_get_health")


@patch("asyncio.create_task")
@patch("asyncio.get_running_loop", return_value=loop)
def test_LocalServerHandlerWorker_send_request_to_master(loop_mock, create_task_mock):
    """Check that the request is sent to master node."""

    class ClientMock:
        def send_request(self, request):
            pass

    class NodeMock:
        def __init__(self):
            self.client = None

    class ServerMock:
        def __init__(self):
            self.node = NodeMock()

    server_mock = ServerMock()
    lshw = LocalServerHandlerWorker(server=server_mock, loop=loop, fernet_key=None, cluster_items={})

    with pytest.raises(WazuhClusterError, match=".* 3023 .*"):
        lshw.send_request_to_master(command=b"test", arguments=b"raises")

    server_mock.node.client = ClientMock()
    with patch.object(server_mock.node.client, "send_request") as send_request_mock:
        assert lshw.send_request_to_master(command=b"test", arguments=b"wazuh") == \
               (b"ok", b"Sent request to master node")
        send_request_mock.assert_called_once_with(b"test", b"wazuh")
        create_task_mock.assert_called_once()


@patch("asyncio.create_task")
@patch("asyncio.get_running_loop", return_value=loop)
def test_LocalServerHandlerWorker_get_api_response(loop_mock, create_task_mock):
    """Check that the response sent by the master is sent to the local client."""

    class FutureMock:
        def result(self):
            pass

    class ClientMock:
        def send_request(self, request):
            pass

    class NodeMock:
        def __init__(self):
            self.client = None

    class ServerMock:
        def __init__(self):
            self.node = NodeMock()

    server_mock = ServerMock()
    lshw = LocalServerHandlerWorker(server=server_mock, loop=loop, fernet_key=None, cluster_items={})
    server_mock.node.client = ClientMock()
    future = FutureMock()
    with patch.object(lshw, "send_request") as send_request_mock:
        lshw.get_api_response(in_command=b"dapi", future=future)
        send_request_mock.assert_called_once_with(command=b"dapi_res", data=future.result())
        create_task_mock.assert_called_once()


@patch("asyncio.create_task")
@patch("asyncio.get_running_loop", return_value=loop)
def test_LocalServerHandlerWorker_send_file_request(loop_mock, create_task_mock):
    """Check that the task for sending files is created."""

    class ClientMock:
        def send_file(self, path):
            pass

    class NodeMock:
        def __init__(self):
            self.client = None

    class ServerMock:
        def __init__(self):
            self.node = NodeMock()

    server_mock = ServerMock()
    lshw = LocalServerHandlerWorker(server=server_mock, loop=loop, fernet_key=None, cluster_items={})

    with pytest.raises(WazuhClusterError, match=".* 3023 .*"):
        lshw.send_file_request(path="/tmp", node_name="worker1")

    server_mock.node.client = ClientMock()
    with patch.object(server_mock.node.client, "send_file") as send_file_mock:
        assert lshw.send_file_request(path="/tmp", node_name="worker1") == (b"ok", b"Forwarding file to master node")
        send_file_mock.assert_called_once_with("/tmp")
        create_task_mock.assert_called_once()


@patch("asyncio.get_running_loop", return_value=loop)
def test_LocalServerWorker_init(loop_mock):
    """Check and set the behaviour of the LocalServerWorker's constructor."""

    class NodeMock:
        def __init__(self):
            self.local_server = None

    node = NodeMock()
    lsw = LocalServerWorker(node=node, performance_test=0, concurrency_test=0,
                            configuration={}, cluster_items={}, enable_ssl=True)
    assert lsw.handler_class == LocalServerHandlerWorker
