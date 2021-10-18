# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import abc
import asyncio
import hashlib
import json
import logging
import os
import sys
from asyncio.events import AbstractEventLoop
from datetime import datetime
from unittest.mock import patch, MagicMock

import cryptography
import pytest

from wazuh import Wazuh
from wazuh.core import exception

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        import wazuh.core.cluster.common as cluster_common
        import wazuh.core.cluster.master as master
        import wazuh.core.cluster.server as server
        import wazuh.core.results as wresults

# Globals

resp = cluster_common.Response()
in_buffer = cluster_common.InBuffer()
cluster_items = {"etc/":
                 {"permissions": "0o640", "source": "master", "files": ["client.keys"],
                  "description": "client keys file database"}, "intervals":
                      {"worker": {"sync_integrity": 9, "sync_agent_info": 10, "sync_agent_info_ko_retry": 1,
                                  "keep_alive": 60, "connection_retry": 10, "max_failed_keepalive_attempts": 2},
                       "master": {"recalculate_integrity": 8, "check_worker_lastkeepalive": 60,
                                  "max_allowed_time_without_keepalive": 120},
                       "communication": {"timeout_cluster_request": 20, "timeout_dapi_request": 200,
                                         "timeout_receiving_file": 120}
                       }
                 }

fernet_key = "00000000000000000000000000000000"
wazuh_common = cluster_common.WazuhCommon()


# Test Response class methods

async def test_response():
    """Test for the 'write' method that belongs to the Response class"""

    with patch('asyncio.Event.wait') as wait_mock:
        with patch('asyncio.Event.set') as set_mock:
            await resp.read()
            resp.write(b"some content")

            assert resp.content == b"some content"

            wait_mock.assert_called_once()
            set_mock.assert_called_once()


# Test InBuffer class methods

@patch('struct.unpack')
def test_inbuffer_get_info_from_header(unpack_mock):
    """Test the method 'get_info_from_header' that belongs to InBuffer class"""

    unpack_mock.return_value = (0, 2048, b'pwd')

    assert isinstance(in_buffer.get_info_from_header(b"header", "hhl", 1), bytes)
    assert in_buffer.get_info_from_header(b"header", "hhl", 1) == b"eader"

    assert in_buffer.counter == 0
    assert in_buffer.total == 2048
    assert in_buffer.cmd == b"pw"
    assert in_buffer.flag_divided == b"d"
    assert in_buffer.payload == bytearray(in_buffer.total)

    unpack_mock.return_value = (0, 2048, b'echo')
    in_buffer.get_info_from_header(b"header", "hhl", 1)
    assert in_buffer.flag_divided == b""


def test_inbuffer_receive_data():
    """Test the 'receive_data' method that belongs to the InBuffer class"""

    in_buffer = cluster_common.InBuffer()
    in_buffer.total = 2048
    in_buffer.received = 1024

    assert isinstance(in_buffer.receive_data(b"data"), bytes)
    assert in_buffer.received == 1028


# Test ReceiveStringTask methods

@patch('wazuh.core.cluster.common.WazuhCommon')
@patch('logging.Logger')
def test_rst_str_method(logger_mock, wazuh_common_mock):
    """Test the '__str__' method.

    Parameters
    ----------
    logger_mock : Mock Object
    wazuh_common_mock : Mock Object
    """

    with patch('wazuh.core.cluster.common.ReceiveStringTask.set_up_coro'):
        with patch('asyncio.create_task'):
            string_task = cluster_common.ReceiveStringTask(wazuh_common_mock, logger_mock, b"task")
            assert isinstance(string_task.__str__(), str)
            assert string_task.__str__() == "task"


@patch('wazuh.core.cluster.common.WazuhCommon')
@patch('logging.Logger')
def test_rst_set_up_coro_ko(logger_mock, wazuh_common_mock):
    """Test the 'set_up_cor' method.

    Parameters
    ----------
    logger_mock : Mock Object
    wazuh_common_mock : Mock Object
    """

    with pytest.raises(NotImplementedError):
        cluster_common.ReceiveStringTask(wazuh_common_mock, logger_mock, b"task")


@patch('asyncio.create_task')
@patch('wazuh.core.cluster.common.ReceiveStringTask.set_up_coro')
@patch('asyncio.get_running_loop')
def test_rst_done_callback(running_loop_mock, set_up_coro_mock, create_task_mock):
    """Test the 'done_callback' method.

    Parameters
    ----------
    running_loop_mock : Mock Object
    set_up_coro_mock : Mock Object
    create_task_mock : Mock Object
    """
    class LoggerMock:
        def __init__(self):
            self.exc = None

        def error(self, exc):
            self.exc = exc

    logger_mock = LoggerMock()

    abstract_server = server.AbstractServer(1, 1, {"config": "config"}, cluster_items, True)
    abstract_server_handler = server.AbstractServerHandler(abstract_server, asyncio.AbstractEventLoop,
                                                           fernet_key, cluster_items)
    master_handler = master.MasterHandler(server=abstract_server_handler, loop=AbstractEventLoop,
                                          fernet_key=fernet_key, cluster_items=cluster_items)

    receive_string_task = cluster_common.ReceiveStringTask(master_handler, logger_mock, b"task")
    master_handler.in_str = {b"task": "some_task"}
    master_handler.sync_tasks = {b"task": "some_task"}
    receive_string_task.task = asyncio.Future()
    receive_string_task.task.set_exception(exception.WazuhClusterError(1001))

    receive_string_task.done_callback()
    assert master_handler.in_str == {}
    assert master_handler.sync_tasks == {}
    assert isinstance(logger_mock.exc, exception.WazuhClusterError)


# Test ReceiveFileTask methods

@patch('wazuh.core.cluster.common.WazuhCommon')
@patch('logging.Logger')
def test_rft_str_method(logger_mock, wazuh_common_mock):
    """Test the '__str__' method.

    Parameters
    ----------
    logger_mock : Mock Object
    wazuh_common_mock : Mock Object
    """

    with patch('wazuh.core.cluster.common.ReceiveFileTask.set_up_coro'):
        with patch('asyncio.create_task'):
            file_task = cluster_common.ReceiveFileTask(wazuh_common_mock, logger_mock, b"task")
            assert isinstance(file_task.__str__(), str)


@patch('wazuh.core.cluster.common.WazuhCommon')
@patch('logging.Logger')
def test_rft_set_up_coro(logger_mock, wazuh_common_mock):
    """Test the 'set_up_cor' method.

    Parameters
    ----------
    logger_mock : Mock Object
    wazuh_common_mock : Mock Object
    """

    with pytest.raises(NotImplementedError):
        cluster_common.ReceiveFileTask(wazuh_common_mock, logger_mock, b"task")


@patch('asyncio.create_task')
@patch('wazuh.core.cluster.common.ReceiveFileTask.set_up_coro')
@patch('asyncio.get_running_loop')
def test_rft_done_callback(running_loop_mock, set_up_coro_mock, create_task_mock):
    """Test the 'done_callback' method.

    Parameters
    ----------
    running_loop_mock : Mock Object
    set_up_coro_mock : Mock Object
    create_task_mock : Mock Object
    """
    class LoggerMock:
        def __init__(self):
            self.exc = None

        def error(self, exc):
            self.exc = exc

    logger_mock = LoggerMock()

    abstract_server = server.AbstractServer(1, 1, {"config": "config"}, cluster_items, True)
    abstract_server_handler = server.AbstractServerHandler(abstract_server, asyncio.AbstractEventLoop,
                                                           fernet_key, cluster_items)
    master_handler = master.MasterHandler(server=abstract_server_handler, loop=AbstractEventLoop,
                                          fernet_key=fernet_key, cluster_items=cluster_items)

    receive_file_task = cluster_common.ReceiveFileTask(master_handler, logger_mock, b"task")
    master_handler.sync_tasks = {"task": "some_task"}
    receive_file_task.task = asyncio.Future()
    receive_file_task.task.set_exception(exception.WazuhClusterError(1001))

    receive_file_task.done_callback()
    assert master_handler.sync_tasks == {}
    assert isinstance(logger_mock.exc, exception.WazuhClusterError)


# Test Handler class methods

def test_handler_push():
    """Test the 'push' method"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    handler.transport = asyncio.WriteTransport
    with patch('asyncio.WriteTransport.write') as write_mock:
        handler.push(b"message")
        write_mock.assert_called_once()


def test_handler_next_counter():
    """Test the 'next_counter' method"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    assert isinstance(handler.next_counter(), int)


def test_handler_msg_build_ok():
    """Test the 'message_build' method"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    # Test first if
    assert isinstance(handler.msg_build(b"command", 12345, b"data"), list)
    assert isinstance(handler.msg_build(b"command", 12345, b"data")[0], bytearray)

    # Test first else
    handler.request_chunk = 100
    assert isinstance(handler.msg_build(b"command", 12345, b"data"), list)
    assert isinstance(handler.msg_build(b"command", 12345, b"data")[0], bytearray)


def test_handler_msg_build_ko():
    """Test the 'message_build' method and check if it is raising the exceptions properly"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with pytest.raises(exception.WazuhClusterError, match=r'.* 3024 .*'):
        handler.msg_build(b"much much longer command", 12345, b"data")


def test_handler_msg_parse():
    """Test the 'msg_handler' method is properly working"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    # self.in_buffer is False
    assert handler.msg_parse() is False

    # Test nested if
    handler.in_buffer = b"much much longer command"
    assert handler.msg_parse() is True

    # Test nested else
    handler.in_msg.received = 1
    handler.in_buffer = b"command"
    assert handler.msg_parse() is True


def test_handler_get_messages_ok():
    """Test the 'get_messages' method"""
    handler = cluster_common.Handler(fernet_key, cluster_items)
    yield_value = None

    with patch('cryptography.fernet.Fernet.decrypt', return_value="decrypted payload"):
        with patch('wazuh.core.cluster.common.Handler.msg_parse', return_value=True) as handler_mock:

            # Test if
            handler.in_msg.total = handler.in_msg.received
            for i in handler.get_messages():
                handler_mock.return_value = False
                yield_value = i
            assert yield_value == ('', 0, 'decrypted payload', b'')

            # Test else
            handler.in_msg.total = handler.in_msg.received + 10
            handler_mock.return_value = True
            for i in handler.get_messages():
                handler_mock.return_value = False


def test_handler_get_messages_ko():
    """Test the 'get_messages' method"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with patch('wazuh.core.cluster.common.Handler.msg_parse', return_value=True):
        with patch('cryptography.fernet.Fernet.decrypt', side_effect=cryptography.fernet.InvalidToken):
            with pytest.raises(exception.WazuhClusterError, match='3025'):
                handler.in_msg.total = 0
                list(handler.get_messages())


async def test_handler_send_request_ok():
    """Test the 'send_request' method"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with patch('wazuh.core.cluster.common.Handler.msg_build', return_values=["some", "messages"]):
        with patch('wazuh.core.cluster.common.Handler.push'):
            with patch('asyncio.wait_for', return_value="some value"):
                assert (await handler.send_request(b'some bytes', b'some data') == "some value")

    with patch('wazuh.core.cluster.common.Handler.msg_build', return_values=["some", "messages"]):
        with patch('wazuh.core.cluster.common.Handler.push'):
            with patch('asyncio.wait_for', side_effect=asyncio.TimeoutError):
                assert (await handler.send_request(b'some bytes', b'some data') == b'Error sending request: '
                                                                                   b'timeout expired.')


async def test_handler_send_request_ko():
    """Test the 'send_request' method proper exception raise"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with patch('wazuh.core.cluster.common.Handler.msg_build', side_effect=MemoryError):
        with pytest.raises(exception.WazuhClusterError, match=r'.* 3026 .*'):
            await handler.send_request(b'some bytes', b'some data')

    with pytest.raises(exception.WazuhClusterError, match=r'.* 3018 .*'):
        await handler.send_request(b'some bytes', b'some data')


async def test_handler_send_file_ok():
    """Test the 'send_file' method"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with patch('os.path.exists', return_value=True):
        with patch('wazuh.core.cluster.common.Handler.send_request', return_value=b"some data"):
            with patch('builtins.open'):
                with patch('hashlib.sha256'):
                    assert (await handler.send_file("some_file.txt") == b'File sent')


async def test_handler_send_file_ko():
    """Test the 'send_file' method exception raise"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with pytest.raises(exception.WazuhClusterError, match=r'.* 3034 .*'):
        await handler.send_file("some_file.txt")


async def test_handler_send_string():
    """Test the 'send_string' method"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with patch('wazuh.core.cluster.common.Handler.send_request', return_value=b"some data"):
        assert (await handler.send_string(b"something") == b"some data")

    with patch('wazuh.core.cluster.common.Handler.send_request', return_value=b"Error"):
        assert (await handler.send_string(b"something") == b"Error")


def test_handler_get_manager():
    """Test the 'get_manager' method"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with pytest.raises(NotImplementedError):
        handler.get_manager()


async def test_handler_forward_dapi_response_ok():
    """Test the 'forward_dapi_response' method"""

    class ParentManager:
        def __init__(self) -> None:
            self.local_server = self.LocalServer()

        class LocalServer:
            def __init__(self) -> None:
                self.clients = {"client": self}

            async def send_string(self, data):
                return data

            async def send_request(self, data, res):
                return res

    handler = cluster_common.Handler(fernet_key, cluster_items)
    handler.in_str = {b"string_id": in_buffer, b"other_string": "some value"}
    mock_manager = ParentManager()

    with patch('wazuh.core.cluster.common.Handler.get_manager', return_value=mock_manager):
        await handler.forward_dapi_response(b"client string_id")
        assert handler.in_str == {b'other_string': 'some value'}


async def test_handler_forward_dapi_response_ko():
    """Test the exceptions present in 'forward_dapi_response' method"""

    class ParentManager:
        def __init__(self) -> None:
            self.local_server = self.LocalServer()

        class LocalServer:
            def __init__(self) -> None:
                self.clients = {"client": self}

            async def send_string(self, data):
                return data

    handler = cluster_common.Handler(fernet_key, cluster_items)
    handler.in_str = {b"string_id": in_buffer, b"other_string": "some value"}
    mock_manager = ParentManager()

    with patch('wazuh.core.cluster.common.Handler.get_manager', return_value=mock_manager):
        # Mock the functions with the expected exceptions
        with patch.object(mock_manager.local_server, "send_string",
                          side_effect=exception.WazuhException(1001)) as send_string_mock:
            with patch.object(logging.getLogger('wazuh'), "error") as logger_mock:
                with patch('wazuh.core.cluster.common.Handler.send_request', return_value="some value"):
                    with patch('json.dumps', return_value="some value"):
                        await handler.forward_dapi_response(b"client string_id")
                        assert handler.in_str == {b'other_string': 'some value'}
                        logger_mock.assert_called_once_with(f"Error sending API response to local client: "
                                                            f"{exception.WazuhException(1001)}")

                        send_string_mock.side_effect = Exception
                        await handler.forward_dapi_response(b"client string_id")
                        logger_mock.assert_called_with("Error sending API response to local client: "
                                                       "b'string_id'")


async def test_handler_forward_sendsync_response_ok():
    """Test the 'forward_sendsync_response' method"""

    class ParentManager:
        def __init__(self) -> None:
            self.local_server = self.LocalServer()

        class LocalServer:
            def __init__(self) -> None:
                self.clients = {"client": self}

            async def send_request(self, data, res):
                return res

    handler = cluster_common.Handler(fernet_key, cluster_items)
    handler.in_str = {b"string_id": in_buffer, b"other_string": "some value"}
    mock_manager = ParentManager()

    with patch('wazuh.core.cluster.common.Handler.get_manager', return_value=mock_manager):
        await handler.forward_sendsync_response(b"client string_id")
        assert handler.in_str == {b'other_string': 'some value'}


async def test_handler_forward_sendsync_response_ko():
    """Test the exceptions present in 'forward_sendsync_response' method"""
    class ParentManager:
        def __init__(self) -> None:
            self.local_server = self.LocalServer()

        class LocalServer:
            def __init__(self) -> None:
                self.clients = {"client": self}

            async def send_request(self, data, res):
                return res

    handler = cluster_common.Handler(fernet_key, cluster_items)
    handler.in_str = {b"string_id": in_buffer, b"other_string": "some value"}
    mock_manager = ParentManager()

    with patch('wazuh.core.cluster.common.Handler.get_manager', return_value=mock_manager):
        # Mock the functions with the expected exceptions
        with patch.object(mock_manager.local_server, "send_request",
                          side_effect=exception.WazuhException(1001)) as send_request_mock:
            with patch.object(logging.getLogger('wazuh'), "error") as logger_mock:
                with patch('wazuh.core.cluster.common.Handler.send_request', return_value="some value"):
                    with patch('json.dumps', return_value="some value"):
                        await handler.forward_sendsync_response(b"client string_id")
                        assert handler.in_str == {b'other_string': 'some value'}
                        logger_mock.assert_called_once_with(f"Error sending send sync response to local client: "
                                                            f"{exception.WazuhException(1001)}")

                        send_request_mock.side_effect = Exception
                        await handler.forward_sendsync_response(b"client string_id")
                        logger_mock.assert_called_with("Error sending send sync response to local client: "
                                                       "b'string_id'")


def test_handler_data_received_ok():
    """Test the 'data_received' proper functioning"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    # Test first if
    with patch('wazuh.core.cluster.common.Handler.get_messages', return_value=[(b"bytes1", 123, b"bytes2", b"d")]):
        # Test try
        handler.data_received(b"message")
        assert handler.div_msg_box[123] == b'bytes2'

        # Test except
        handler.div_msg_box = {123: b"bytes"}
        handler.data_received(b"message")
        assert handler.div_msg_box[123] == b'bytesbytes2'

    # Test first else and first nested if
    with patch('wazuh.core.cluster.common.Handler.get_messages', return_value=[(b"bytes1", 123, b"bytes2", b"bytes3")]):
        with patch('cryptography.fernet.Fernet.decrypt', return_value="decrypted payload"):
            # Test second nested if and the else inside of it
            with patch('asyncio.WriteTransport.write') as write_mock:
                handler.box = {123: asyncio.WriteTransport}
                handler.data_received(b"message")
                write_mock.assert_called_once()

            # Test second nested if and the if inside of it
            handler.box = {123: None}
            handler.data_received(b"message")
            assert 123 not in handler.box

            # Test second nested else
            with patch('wazuh.core.cluster.common.Handler.dispatch') as dispatch_mock:
                handler.data_received(b"message")
                dispatch_mock.assert_called_once_with(b"bytes1", 123, b"bytes2")


def test_handler_data_received_ko():
    """Test the 'data_received' function exceptions"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with patch('wazuh.core.cluster.common.Handler.get_messages', return_value=[(b"bytes1", 123, b"bytes2", b"bytes3")]):
        with patch('cryptography.fernet.Fernet.decrypt', side_effect=cryptography.fernet.InvalidToken):
            with pytest.raises(exception.WazuhClusterError, match=r'.* 3025 .*'):
                handler.div_msg_box = {123: b"bytes"}
                handler.data_received(b"message")


@patch('wazuh.core.cluster.common.Handler.msg_build', return_value=["msg"])
@patch('wazuh.core.cluster.common.Handler.push')
@patch('wazuh.core.cluster.common.Handler.process_request', return_value=(b"command", b"payload"))
def test_handler_dispatch(process_request_mock, push_mock, msg_build_mock):
    """Test the 'dispatch' function"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    # Test the first try and if
    handler.dispatch(b"command", 123, b"payload")
    process_request_mock.assert_called_once_with(b"command", b"payload")
    push_mock.assert_called_once_with("msg")
    msg_build_mock.assert_called_once_with(b"command", 123, b"payload")

    # Test the first except
    process_request_mock.side_effect = exception.WazuhException(1001)
    with patch.object(logging.getLogger('wazuh'), "error") as logger_mock:
        handler.dispatch(None, 123, b"payload")
        logger_mock.assert_called_with(f"Internal error processing request '{None}': {exception.WazuhException(1001)}")

        # Test the second except
        process_request_mock.side_effect = Exception
        handler.dispatch(None, 123, b"payload")
        logger_mock.assert_called_with(f"Unhandled error processing request '{None}': ", exc_info=True)


def test_handler_close():
    """Test the 'close' function"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    class TransportMock:

        def close():
            pass

    handler.transport = TransportMock()

    with patch.object(TransportMock, "close") as close_mock:
        handler.close()
        close_mock.assert_called_once()


def test_handler_process_request():
    """Test the 'process_request' function"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with patch('wazuh.core.cluster.common.Handler.echo') as echo_mock:
        handler.process_request(b"echo", b"data")
        echo_mock.assert_called_once_with(b"data")
    with patch('wazuh.core.cluster.common.Handler.receive_file') as receive_file_mock:
        handler.process_request(b"new_file", b"data")
        receive_file_mock.assert_called_once_with(b"data")
    with patch('wazuh.core.cluster.common.Handler.receive_str') as receive_str_mock:
        handler.process_request(b"new_str", b"data")
        receive_str_mock.assert_called_once_with(b"data")
    with patch('wazuh.core.cluster.common.Handler.update_file') as update_file_mock:
        handler.process_request(b"file_upd", b"data")
        update_file_mock.assert_called_once_with(b"data")
    with patch('wazuh.core.cluster.common.Handler.str_upd') as str_upd_mock:
        handler.process_request(b"str_upd", b"data")
        str_upd_mock.assert_called_once_with(b"data")
    with patch('wazuh.core.cluster.common.Handler.process_error_str') as process_error_str_mock:
        handler.process_request(b"err_str", b"data")
        process_error_str_mock.assert_called_once_with(b"data")
    with patch('wazuh.core.cluster.common.Handler.end_file') as end_file_mock:
        handler.process_request(b"file_end", b"data")
        end_file_mock.assert_called_once_with(b"data")
    with patch('wazuh.core.cluster.common.Handler.process_unknown_cmd') as process_unknown_cmd_mock:
        handler.process_request(b"something random", b"data")
        process_unknown_cmd_mock.assert_called_once_with(b"something random")


def test_handler_process_response():
    """Test the 'process_response' function"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    assert handler.process_response(b'ok', b"payload") == b"payload"

    with patch('wazuh.core.cluster.common.Handler.process_error_from_peer', return_value=b"payload"):
        assert handler.process_response(b"err", b"payload") == b"payload"

    assert handler.process_response(b"command", b"payload") == b"Unkown response command received: command"


def test_handler_echo():
    """Test the 'echo' function"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    assert handler.echo(b"data") == (b"ok", b"data")


def test_handler_receive_file():
    """Test the 'receive_files' function"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    assert handler.receive_file(b"data") == (b"ok ", b"Ready to receive new file")


def test_handler_update_file():
    """Test the 'update_files' function"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with patch('builtins.open'):
        with open(os.path.join(os.getcwd(), "no_file.txt")) as f:
            handler.in_file = {b"filepath": {"fd": f, "checksum": hashlib.sha256()}}
            assert handler.update_file(b"filepath data") == (b"ok", b"File updated")


def test_handler_end_file():
    """Test the 'end_file' function"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    class ChecksumMock:

        def digest(self):
            return b"checksum"

    with patch('builtins.open'):
        with open(os.path.join(os.getcwd(), "no_file.txt")) as f:
            handler.in_file = {b"name": {"fd": f, "checksum": ChecksumMock()}}
            # Test the first condition
            assert handler.end_file(b"name checksum") == (b"ok", b"File received correctly")

            handler.in_file = {b"name": {"fd": f, "checksum": hashlib.sha256()}}
            # Test the second condition
            assert handler.end_file(b"name checksum") == (b"err",
                                                          b"File wasn't correctly received. Checksums aren't equal.")


def test_handler_receive_str():
    """Test the 'receive_str' function"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    reply, name = handler.receive_str(b"10")
    assert reply == b"ok"
    assert isinstance(name, bytes)


def test_handler_str_upd():
    """Test the 'str_upd' function"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with patch('wazuh.core.cluster.common.InBuffer.receive_data'):
        handler.in_str = {b"string_id": in_buffer}
        assert handler.str_upd(b"string_id data") == (b"ok", b"String updated")


def test_handler_process_error_str():
    """Test the 'process_error_str' function"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    # Test no conditioned return
    assert handler.process_error_str(b"120") == (b'ok', b'None')

    # Test return inside loop and condition
    handler.in_str = {b"string_id": in_buffer}
    assert handler.process_error_str(b"2048") == (b'ok', b'string_id')


def test_handler_process_unknown_cmd():
    """Test the 'process_unknown_cmd' function"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    assert handler.process_unknown_cmd(b"unknown") == (b'err', "unknown command 'b'unknown''".encode())


def test_handler_process_error_from_peer():
    """Test the 'process_error_from_peer' correct functioning"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with patch('json.loads', return_value="some value"):
        assert handler.process_error_from_peer(b"data to decode") == "some value"


def test_handler_process_error_from_peer_ko():
    """Test the 'process_error_from_peer' correct functioning"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    assert isinstance(handler.process_error_from_peer(b"data to decode"), exception.WazuhClusterError)


def test_handler_setup_task_logger():
    """Test the 'set_task_logger' correct functioning"""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    assert isinstance(handler.setup_task_logger("task_tag"), logging.Logger)


# Test 'WazuhCommon' class methods

def test_wazuh_common_get_logger():
    """Test the 'get_logger' correct functioning"""

    with pytest.raises(NotImplementedError):
        wazuh_common.get_logger()


def test_wazuh_common_setup_receive_file():
    """Test the 'setup_receive_file' correct functioning"""

    class MyTaskMock:

        def __init__(self) -> None:
            self.task_id = "key"

    my_task = MyTaskMock()
    mock_object = MagicMock(return_value=my_task)

    with patch('wazuh.core.cluster.common.WazuhCommon.get_logger') as logger_mock:
        first_output, second_output = wazuh_common.setup_receive_file(mock_object)
        logger_mock.assert_called_once()
        assert first_output == b'ok'
        assert isinstance(second_output, bytes)


@patch('wazuh.core.cluster.common.WazuhCommon')
@patch('logging.Logger')
def test_wazuh_common_end_receiving_file_ok(logger_mock, wazuh_common_mock):
    """Test the 'end_receiving_file' correct functioning"""

    with patch('wazuh.core.cluster.common.ReceiveFileTask.set_up_coro'):
        with patch('asyncio.create_task'):
            file_task = cluster_common.ReceiveFileTask(wazuh_common_mock, logger_mock, b"task")

    wazuh_common.sync_tasks = {'task_ID': file_task}
    assert wazuh_common.end_receiving_file("task_ID filepath") == (b'ok', b'File correctly received')


def test_wazuh_common_end_receiving_file_ko():
    """Test the 'end_receiving_file' correct functioning in a failure scenario"""

    with patch('os.path.exists', return_value=True):
        with patch('os.remove') as os_remove_mock:
            with pytest.raises(exception.WazuhClusterError, match=r'.* 3027 .*'):
                wazuh_common.end_receiving_file("not_task_ID filepath")

            with patch('wazuh.core.cluster.common.WazuhCommon.get_logger'):
                with pytest.raises(exception.WazuhClusterError, match=r'.* 3027 .*'):
                    os_remove_mock.side_effect = Exception
                    wazuh_common.end_receiving_file("not_task_ID filepath")
                    os_remove_mock.assert_called_once_with(Exception)


def test_wazuh_common_error_receiving_file_ok():
    """Test the 'error_receiving_file' correct functioning"""

    with patch('json.loads'):
        with patch('os.path.exists', return_value=True):
            with patch('os.remove'):
                # Test first condition and its nested condition
                assert wazuh_common.error_receiving_file("task_ID error_details") == (b'ok', b'Error received')

        # Test second condition
        with patch('wazuh.core.cluster.common.WazuhCommon.get_logger'):
            assert wazuh_common.error_receiving_file("not_task_ID error_details") == (b'ok', b'Error received')


def test_wazuh_common_error_receiving_file_ko():
    """Test the 'error_receiving_file' when an exception takes place"""

    with patch('json.loads'):
        with patch('os.path.exists', return_value=True):
            with patch('os.remove', side_effect=Exception):

                with patch('wazuh.core.cluster.common.WazuhCommon.get_logger'):
                    assert wazuh_common.error_receiving_file("task_ID error_details") == (b'ok', b'Error received')


def test_wazuh_common_get_node():
    """Test the 'get_node' correct functioning"""

    class MockClass(cluster_common.WazuhCommon, cluster_common.Handler):
        def __init__(self):
            super().__init__()

    class MockManager:
        def get_node(self):
            pass

    mock_class = MockClass()
    mock_manager = MockManager()

    with patch('wazuh.core.cluster.common.Handler.get_manager', return_value=mock_manager) as manager_mock:
        mock_class.get_node()
        manager_mock.assert_called_once()


def test_asyncio_exception_handler():
    """Test the 'asyncio_exception_handler' correct functioning"""

    with patch.object(logging, "error") as mock_logging:
        with patch('asyncio.new_event_loop') as mock_loop:
            with patch('traceback.format_tb', return_value="traceback"):
                cluster_common.asyncio_exception_handler(mock_loop, {'exception': Exception, 'message': "Some message"})
                output = "tUnhandled exception: <class 'Exception'> Some message\n" \
                         "rUnhandled exception: <class 'Exception'> Some message\n" \
                         "aUnhandled exception: <class 'Exception'> Some message\n" \
                         "cUnhandled exception: <class 'Exception'> Some message\n" \
                         "eUnhandled exception: <class 'Exception'> Some message\n" \
                         "bUnhandled exception: <class 'Exception'> Some message\n" \
                         "aUnhandled exception: <class 'Exception'> Some message\n" \
                         "cUnhandled exception: <class 'Exception'> Some message\n" \
                         "k"

                mock_logging.assert_called_once_with(output)


def test_WazuhJSONEcoder_default():
    """Test the 'default' method"""

    wazuh_encoder = cluster_common.WazuhJSONEncoder()

    # Test first condition
    assert isinstance(wazuh_encoder.default(object), dict)
    assert wazuh_encoder.default(object) == {'__callable__': {'__name__': 'object', '__module__': 'builtins',
                                                              '__qualname__': 'object', '__type__': 'type'}}

    class WazuhMock(json.JSONEncoder):
        __self__ = Wazuh()
        a = 0
        b = 0

        def __init__(self) -> None:
            self.a = 0
            self.b = 0

    wazuh_encoder.default(WazuhMock)

    with patch('builtins.callable', return_value=False):

        # Test second condition
        assert isinstance(wazuh_encoder.default(exception.WazuhException(3011)), dict)
        assert wazuh_encoder.default(exception.WazuhException(3011)) == \
               {'__wazuh_exception__': {'__class__': 'WazuhException',
                                        '__object__': {'type': 'about:blank', 'title': 'WazuhException', 'code': 3011,
                                                       'extra_message': None, 'extra_remediation': None,
                                                       'cmd_error': False, 'dapi_errors': {}}}}

        # Test third condition
        abstract_wazuh_result = wresults.AffectedItemsWazuhResult()

        assert isinstance(wazuh_encoder.default(abstract_wazuh_result), dict)
        assert wazuh_encoder.default(abstract_wazuh_result) == \
               {'__wazuh_result__': {'__class__': 'AffectedItemsWazuhResult',
                                     '__object__': {'affected_items': [], 'sort_fields': None, 'sort_casting': ['int'],
                                                    'sort_ascending': [True], 'total_affected_items': 0,
                                                    'total_failed_items': 0, 'dikt': {}, 'all_msg': '', 'some_msg': '',
                                                    'none_msg': '', 'failed_items_keys': [],
                                                    'failed_items_values': []}}}

        # Test fourth condition
        date = datetime(2021, 10, 15)
        assert isinstance(wazuh_encoder.default(date), dict)
        assert wazuh_encoder.default(date) == {'__wazuh_datetime__': '2021-10-15T00:00:00Z'}

        # Test simple return
        with pytest.raises(TypeError):
            wazuh_encoder.default({"key": "value"})


def test_as_wazuh_object_ok():
    """Test 'as_wazuh_object' method"""

    # Test the first condition and nested if
    assert cluster_common.as_wazuh_object({"__callable__": {"__name__": "type", "__wazuh__": "version"}}) == "server"

    # Test the first condition and nested else
    assert cluster_common.as_wazuh_object({"__callable__": {"__name__": "__name__", "__qualname__": "__loader__.value",
                                                            "__module__": "math"}}) == "BuiltinImporter"

    assert cluster_common.as_wazuh_object({"__callable__": {"__name__": "__name__", "__qualname__": "value",
                                                            "__module__": "itertools"}}) == "itertools"

    # Test the second condition
    assert isinstance(cluster_common.as_wazuh_object(
        {"__wazuh_exception__": {"__class__": "WazuhException", "__object__": {"code": 1001}}}),
        exception.WazuhException)

    # Test the third condition
    with patch('wazuh.core.results.AbstractWazuhResult.decode_json', return_value=wresults.AbstractWazuhResult):
        assert isinstance(cluster_common.as_wazuh_object(
            {"__wazuh_result__": {"__class__": "AbstractWazuhResult", "__object__": {"code": 1001}}}), abc.ABCMeta)

    # Test the fourth condition
    assert isinstance(cluster_common.as_wazuh_object({"__wazuh_datetime__": "2021-10-14"}), datetime)
    assert cluster_common.as_wazuh_object({"__wazuh_datetime__": "2021-10-14"}) == datetime(2021, 10, 14)

    # No condition fulfilled
    assert isinstance(cluster_common.as_wazuh_object({"__wazuh_datetime_bad__": "2021-10-14"}), dict)
    assert cluster_common.as_wazuh_object({"__wazuh_datetime_bad__": "2021-10-14"}) == \
           {"__wazuh_datetime_bad__": "2021-10-14"}


def test_as_wazuh_object_ko():
    """Test if the exceptions are correctly raised"""

    with pytest.raises(exception.WazuhInternalError, match=r'.* 1000 .*'):
        cluster_common.as_wazuh_object({"__callable__": {"__name__": "value", "__wazuh__": "value"}})
