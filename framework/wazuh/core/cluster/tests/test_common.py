# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import _hashlib
import _io
import abc
import asyncio
import cryptography
import hashlib
import json
import logging
import os
import pytest
import sys
from contextvars import ContextVar
from datetime import datetime
from unittest.mock import patch, MagicMock
from uuid import uuid4
from uvloop import EventLoopPolicy, new_event_loop
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
        import wazuh.core.results as wresults

# Globals

cluster_items = {"etc/": {"permissions": "0o640", "source": "master", "files": ["client.keys"],
                          "description": "client keys file database"},
                 "intervals": {"worker": {"sync_integrity": 9, "sync_agent_info": 10, "sync_agent_info_ko_retry": 1,
                                          "keep_alive": 60, "connection_retry": 10, "max_failed_keepalive_attempts": 2},
                               "master": {"recalculate_integrity": 8, "check_worker_lastkeepalive": 60,
                                          "max_allowed_time_without_keepalive": 120},
                               "communication": {"timeout_cluster_request": 20, "timeout_dapi_request": 200,
                                                 "timeout_receiving_file": 120}
                               }
                 }

fernet_key = "00000000000000000000000000000000"
wazuh_common = cluster_common.WazuhCommon()
in_buffer = cluster_common.InBuffer()

asyncio.set_event_loop_policy(EventLoopPolicy())
loop = new_event_loop()


# Test Response class methods

@pytest.mark.asyncio
async def test_response_init():
    """Test for the 'init' method that belongs to the Response class"""
    event = asyncio.Event(loop=loop)
    with patch('asyncio.Event', return_value=event):
        response = cluster_common.Response()
        assert response.received_response == event
        assert response.content is None


async def test_response_read():
    """Test for the 'read' method that belongs to the Response class. This method waits until a response is received."""

    with patch('asyncio.Event.wait') as wait_mock:
        response = cluster_common.Response()
        response.content = 'Testing'
        assert await response.read() == 'Testing'
        wait_mock.assert_called_once()


async def test_response_write():
    """Test for the 'write' method that belongs to the Response class. It sets the content of a response and its
    availability."""

    with patch('asyncio.Event.wait') as wait_mock:
        with patch('asyncio.Event.set') as set_mock:
            response = cluster_common.Response()
            await response.read()
            response.write(b"some content")

            assert response.content == b"some content"
            wait_mock.assert_called_once()
            set_mock.assert_called_once()


# Test InBuffer class methods

def test_inbuffer_init():
    """Test the method '__init__' that belongs to InBuffer class."""

    assert in_buffer.counter == 0
    assert in_buffer.total == 0
    assert in_buffer.cmd == ""
    assert in_buffer.flag_divided == b""
    assert in_buffer.payload == bytearray(bytearray(in_buffer.total))


@patch('struct.unpack')
def test_inbuffer_get_info_from_header(unpack_mock):
    """Test if the information contained in a request's header is properly extracted."""

    unpack_mock.return_value = (0, 2048, b'pwd')

    assert isinstance(in_buffer.get_info_from_header(b"header", "hhl", 1), bytes)
    assert in_buffer.get_info_from_header(b"header", "hhl", 1) == b"eader"

    assert in_buffer.counter == 0
    assert in_buffer.total == 2048
    # Test how the first part of the command is being taken as the command, while the second corresponds to the value.
    # If the flag value is the same as divide_flag, we will forward this value to the flag_divided attribute.
    assert in_buffer.cmd == b"pw"
    assert in_buffer.flag_divided == b"d"
    assert in_buffer.payload == bytearray(in_buffer.total)

    unpack_mock.return_value = (0, 2048, b'echo')
    in_buffer.get_info_from_header(b"header", "hhl", 1)
    # In this case the flag value is not equal to divide_flag, thus the flag_divided value will be the default one, b"".
    assert in_buffer.flag_divided == b""
    assert in_buffer.cmd == b"ech"


def test_inbuffer_receive_data():
    """Test if the data is being correctly added to the payload bytearray."""

    in_buffer.total = 2048
    in_buffer.received = 1024

    assert isinstance(in_buffer.receive_data(b"data"), bytes)
    assert in_buffer.received == 1028


# Test ReceiveStringTask methods

@patch("asyncio.create_task")
@patch.object(logging.getLogger("wazuh"), "error")
@patch("wazuh.core.cluster.common.ReceiveStringTask.set_up_coro")
def test_rst_init(setup_coro_mock, logger_mock, create_task_mock):
    """Test the '__init__' method."""

    class TaskMock:

        def __init__(self):
            pass

        def add_done_callback(self):
            pass

    create_task_mock.return_value = TaskMock()

    with patch.object(TaskMock, "add_done_callback") as done_callback_mock:
        string_task = cluster_common.ReceiveStringTask(wazuh_common=cluster_common.WazuhCommon(), logger=logger_mock,
                                                       task_id=b"010")
        assert isinstance(string_task.wazuh_common, cluster_common.WazuhCommon)
        setup_coro_mock.assert_called_once()
        done_callback_mock.assert_called_once()
        assert string_task.logger == logger_mock
        assert string_task.task_id == b"010"
        assert isinstance(string_task.task, TaskMock)


@patch('logging.Logger')
@patch('asyncio.create_task')
@patch('wazuh.core.cluster.common.WazuhCommon')
@patch('wazuh.core.cluster.common.ReceiveStringTask.set_up_coro')
def test_rst_str_method(wazuh_common_mock, create_task_mock, logger_mock, setup_coro_mock):
    """Test the proper output of the '__str__' method."""

    string_task = cluster_common.ReceiveStringTask(wazuh_common_mock, logger_mock, b"task")
    assert isinstance(string_task.__str__(), str)
    assert string_task.__str__() == "task"


@patch('logging.Logger')
@patch('wazuh.core.cluster.common.WazuhCommon')
def test_rst_set_up_coro_ko(wazuh_common_mock, logger_mock):
    """Test if the exception is being properly raised when an Exception takes place."""

    with pytest.raises(NotImplementedError):
        cluster_common.ReceiveStringTask(wazuh_common_mock, logger_mock, b"task")


@patch("asyncio.create_task")
@patch("wazuh.core.cluster.common.ReceiveStringTask.set_up_coro")
def test_rst_done_callback(setup_coro_mock, create_task_mock):
    """Test if this function is properly removing the finished tasks from the queue."""

    class TaskMock:

        def __init__(self):
            pass

        def add_done_callback(self):
            pass

        def cancelled(self):
            return False

        def exception(self):
            return Exception

    class WazuhCommon:

        def __init__(self):
            self.in_str = {b"010": b"123456789", b"011": b"123456789"}
            self.sync_tasks = {b"010": b"123456789", b"011": b"123456789"}

    create_task_mock.return_value = TaskMock()
    wazuh_common_mock = WazuhCommon()

    with patch.object(TaskMock, "add_done_callback"):
        with patch.object(logging.getLogger('wazuh'), "error") as logger_mock:
            string_task = cluster_common.ReceiveStringTask(wazuh_common=wazuh_common_mock,
                                                           logger=logging.getLogger('wazuh'), task_id=b"010")
            string_task.done_callback()
            assert string_task.wazuh_common.in_str == {b"011": b"123456789"}
            assert string_task.wazuh_common.sync_tasks == {b"011": b"123456789"}
            logger_mock.assert_called_once_with(Exception)


# Test ReceiveFileTask methods

@patch('asyncio.Event')
@patch("asyncio.create_task")
@patch.object(logging.getLogger("wazuh"), "error")
@patch("wazuh.core.cluster.common.ReceiveFileTask.set_up_coro")
@patch("wazuh.core.cluster.common.uuid4", return_value="e6c45993-b0ae-438f-8914-3b5175b2bbfd")
def test_rft_init(uuid_mock, setup_coro_mock, logger_mock, create_task_mock, event_mock):
    """Test the '__init__' method."""

    class TaskMock:

        def __init__(self):
            pass

        def add_done_callback(self):
            pass

    create_task_mock.return_value = TaskMock()

    with patch.object(TaskMock, "add_done_callback") as done_callback_mock:
        file_task = cluster_common.ReceiveFileTask(wazuh_common=cluster_common.WazuhCommon(), logger=logger_mock,
                                                   task_id=b"010")
        assert isinstance(file_task.wazuh_common, cluster_common.WazuhCommon)
        setup_coro_mock.assert_called_once()
        done_callback_mock.assert_called_once()
        assert file_task.logger == logger_mock
        assert file_task.task_id == "010"
        assert isinstance(file_task.task, TaskMock)
        event_mock.assert_called_once()
        file_task.filename = ""

        # Test if task_id is None
        string_task = cluster_common.ReceiveFileTask(wazuh_common=cluster_common.WazuhCommon(), logger=logger_mock,
                                                     task_id="")
        assert string_task.task_id == uuid_mock.return_value


@patch('asyncio.Event')
@patch('logging.Logger')
@patch("asyncio.create_task")
@patch("wazuh.core.cluster.common.ReceiveFileTask.set_up_coro")
def test_rft_str_method(set_up_coro_mock, create_task_mock, logger_mock, event_mock):
    """Test the '__str__' method."""

    class TaskMock:

        def __init__(self):
            pass

        def add_done_callback(self):
            pass

    create_task_mock.return_value = TaskMock()

    with patch.object(TaskMock, "add_done_callback"):
        file_task = cluster_common.ReceiveFileTask(wazuh_common=cluster_common.WazuhCommon(), logger=logger_mock,
                                                   task_id=b"010")
        assert isinstance(file_task.__str__(), str)


@patch('logging.Logger')
@patch('wazuh.core.cluster.common.WazuhCommon')
def test_rft_set_up_coro(wazuh_common_mock, logger_mock):
    """Test if the exception is being properly raised when an Exception takes place."""

    with pytest.raises(NotImplementedError):
        cluster_common.ReceiveFileTask(wazuh_common_mock, logger_mock, b"task")


@patch('asyncio.Event')
@patch("asyncio.create_task")
@patch("wazuh.core.cluster.common.ReceiveFileTask.set_up_coro")
def test_rft_done_callback(set_up_coro_mock, create_task_mock, event_mock):
    """Test if this function is properly removing the finished tasks from the queue."""

    class TaskMock:

        def __init__(self):
            pass

        def add_done_callback(self):
            pass

        @staticmethod
        def cancelled():
            return False

        @staticmethod
        def exception():
            return Exception

    class WazuhCommon:

        def __init__(self):
            self.sync_tasks = {"010": b"123456789", "011": b"123456789"}

    create_task_mock.return_value = TaskMock()
    wazuh_common_mock = WazuhCommon()

    with patch.object(TaskMock, "add_done_callback"):
        with patch.object(logging.getLogger('wazuh'), "error") as logger_mock:
            file_task = cluster_common.ReceiveFileTask(wazuh_common=wazuh_common_mock,
                                                       logger=logging.getLogger('wazuh'), task_id=b"010")
            file_task.done_callback()
            assert file_task.wazuh_common.sync_tasks == {"011": b"123456789"}
            logger_mock.assert_called_once_with(Exception)


# Test Handler class methods

def test_handler_init():
    """Test the '__init__' method."""

    class LoggerMock:

        def __init__(self):
            pass

    with patch('wazuh.core.cluster.utils.context_tag', ContextVar('', default="")) as cv:
        handler = cluster_common.Handler(None, cluster_items)

        assert isinstance(handler.counter, int)
        assert handler.box == {}
        assert handler.div_msg_box == {}
        assert handler.cmd_len == 12
        assert handler.header_len == handler.cmd_len + 8
        assert handler.header_format == f'!2I{handler.cmd_len}s'
        assert handler.in_buffer == b''
        assert isinstance(handler.in_msg, cluster_common.InBuffer)
        assert handler.in_file == {}
        assert handler.in_str == {}
        assert handler.request_chunk == 5242880
        assert handler.my_fernet is None
        assert handler.logger == logging.getLogger("wazuh")
        assert handler.tag == "Handler"
        assert handler.cluster_items == cluster_items
        assert handler.transport is None
        assert cv.get() == handler.tag

    # Check other logger and my_fernet behaviors
    assert isinstance(cluster_common.Handler(fernet_key, cluster_items).my_fernet, cryptography.fernet.Fernet)
    assert isinstance(cluster_common.Handler(None, cluster_items, logger=LoggerMock()).logger, LoggerMock)


def test_handler_push():
    """Test if a message is being properly sent to peer."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    handler.transport = asyncio.WriteTransport
    with patch('asyncio.WriteTransport.write') as write_mock:
        handler.push(b"message")
        write_mock.assert_called_once_with(b"message")


def test_handler_next_counter():
    """Test if the counter is being properly increased."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    assert handler.next_counter() == (handler.counter + 1) % (2 ** 32) - 1


def test_handler_msg_build_ok():
    """Test if a message is being built with the right header and payload."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    # Test first if
    assert isinstance(handler.msg_build(b"command", 12345, b"data"), list)
    assert isinstance(handler.msg_build(b"command", 12345, b"data")[0], bytearray)

    # Test first else
    handler.request_chunk = 100
    assert isinstance(handler.msg_build(b"command", 12345, b"data"), list)
    assert isinstance(handler.msg_build(b"command", 12345, b"data")[0], bytearray)


def test_handler_msg_build_ko():
    """Test the 'message_build' method and check if it is raising the exceptions properly."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with pytest.raises(exception.WazuhClusterError, match=r'.* 3024 .*'):
        handler.msg_build(b"much much longer command", 12345, b"data")


def test_handler_msg_parse():
    """Test if an incoming message is being properly parsed."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    # self.in_buffer is False
    assert handler.msg_parse() is False

    # Test nested if
    handler.in_buffer = b"much much longer command"
    assert len(handler.in_buffer) >= handler.header_len
    assert handler.msg_parse() is True

    # Test nested else
    handler.in_msg.received = 1
    handler.in_buffer = b"command"
    assert len(handler.in_buffer) < handler.header_len
    assert handler.msg_parse() is True


def test_handler_get_messages_ok():
    """Test the proper decryption of the received data and returns it in separate yields."""
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
            for _ in handler.get_messages():
                handler_mock.return_value = False


@patch('wazuh.core.cluster.common.Handler.msg_parse', return_value=True)
@patch('cryptography.fernet.Fernet.decrypt', side_effect=cryptography.fernet.InvalidToken)
def test_handler_get_messages_ko(decrypt_mock, msg_parse_mock):
    """Test whether the exception were correctly raised."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with pytest.raises(exception.WazuhClusterError, match=r'.* 3025 .*'):
        handler.in_msg.total = 0
        list(handler.get_messages())


@pytest.mark.asyncio
@patch('wazuh.core.cluster.common.Handler.push')
@patch('asyncio.wait_for', return_value="some value")
@patch('wazuh.core.cluster.common.Handler.next_counter', return_value=30)
@patch('wazuh.core.cluster.common.Handler.msg_build', return_value=["some", "messages"])
async def test_handler_send_request_ok(msg_build_mock, next_counter_mock, wait_for_mock, push_mock):
    """Test if a request is being properly sent."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    assert (await handler.send_request(b'some bytes', b'some data') == "some value")
    assert next_counter_mock.return_value not in handler.box

    wait_for_mock.side_effect = asyncio.TimeoutError
    assert (await handler.send_request(b'some bytes', b'some data') == b'Error sending request: '
                                                                       b'timeout expired.')
    print(handler.box)
    assert handler.box[next_counter_mock.return_value] is None

    msg_build_mock.assert_called_with(b'some bytes', 30, b'some data')
    next_counter_mock.assert_called_with()
    assert wait_for_mock.call_count == 2
    push_mock.assert_called_with("messages")


@pytest.mark.asyncio
async def test_handler_send_request_ko():
    """Test the 'send_request' method proper exception raise."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with patch('wazuh.core.cluster.common.Handler.msg_build', side_effect=MemoryError):
        with pytest.raises(exception.WazuhClusterError, match=r'.* 3026 .*'):
            await handler.send_request(b'some bytes', b'some data')

    with pytest.raises(exception.WazuhClusterError, match=r'.* 3018 .*'):
        await handler.send_request(b'some bytes', b'some data')


@pytest.mark.asyncio
@patch('builtins.open')
@patch('hashlib.sha256')
@patch('os.path.exists', return_value=True)
@patch('wazuh.core.cluster.common.Handler.send_request', return_value=b"some data")
async def test_handler_send_file_ok(send_request_mock, exists_mock, sha256_mock, open_mock):
    """Test if a file is being correctly sent to peer."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    assert (await handler.send_file("some_file.txt") == b'File sent')


@pytest.mark.asyncio
async def test_handler_send_file_ko():
    """Test the 'send_file' method exception raise."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with pytest.raises(exception.WazuhClusterError, match=r'.* 3034 .*'):
        await handler.send_file("some_file.txt")


@pytest.mark.asyncio
async def test_handler_send_string():
    """Test if a large string can be correctly sent to peer."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with patch('wazuh.core.cluster.common.Handler.send_request', return_value=b"some data"):
        assert (await handler.send_string(b"something") == b"some data")

    with patch('wazuh.core.cluster.common.Handler.send_request', return_value=b"Error"):
        with patch.object(logging.getLogger("wazuh"), "error") as logger_mock:
            assert (await handler.send_string(b"something") == b"Error")
            logger_mock.assert_called_once_with(f'There was an error while trying to send a string: {b"Error"}')


def test_handler_get_manager():
    """Test if the exception is being properly raised."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with pytest.raises(NotImplementedError):
        handler.get_manager()


@pytest.mark.asyncio
async def test_handler_forward_dapi_response_ok():
    """Test if a response is being properly forwarded to the manager."""

    class ParentManager:
        def __init__(self) -> None:
            self.local_server = self.LocalServer()

        class LocalServer:
            def __init__(self) -> None:
                self.clients = {"client": self}

            @staticmethod
            async def send_string(data):
                return data

            @staticmethod
            async def send_request(data, res):
                return res

    handler = cluster_common.Handler(fernet_key, cluster_items)
    handler.in_str = {b"string_id": in_buffer, b"other_string": "some value"}
    mock_manager = ParentManager()

    with patch('wazuh.core.cluster.common.Handler.get_manager', return_value=mock_manager):
        await handler.forward_dapi_response(b"client string_id")
        assert handler.in_str == {b'other_string': 'some value'}


@pytest.mark.asyncio
async def test_handler_forward_dapi_response_ko():
    """Test the exceptions present in 'forward_dapi_response' method."""

    class ParentManager:
        def __init__(self) -> None:
            self.local_server = self.LocalServer()

        class LocalServer:
            def __init__(self) -> None:
                self.clients = {"client": self}

            @staticmethod
            async def send_string(data):
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


@pytest.mark.asyncio
async def test_handler_forward_sendsync_response_ok():
    """Test if a 'sendsync' response is being properly forwarded from the master node."""

    class ParentManager:
        def __init__(self) -> None:
            self.local_server = self.LocalServer()

        class LocalServer:
            def __init__(self) -> None:
                self.clients = {"client": self}

            @staticmethod
            async def send_request(data, res):
                return res

    handler = cluster_common.Handler(fernet_key, cluster_items)
    handler.in_str = {b"string_id": in_buffer, b"other_string": "some value"}
    mock_manager = ParentManager()

    with patch('wazuh.core.cluster.common.Handler.get_manager', return_value=mock_manager):
        await handler.forward_sendsync_response(b"client string_id")
        assert handler.in_str == {b'other_string': 'some value'}


@pytest.mark.asyncio
async def test_handler_forward_sendsync_response_ko():
    """Test the exceptions present in 'forward_sendsync_response' method."""

    class ParentManager:
        def __init__(self) -> None:
            self.local_server = self.LocalServer()

        class LocalServer:
            def __init__(self) -> None:
                self.clients = {"client": self}

            @staticmethod
            async def send_request(data, res):
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
    """Test if the data received from other peers is being properly handled."""
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
    """Test the 'data_received' function exceptions."""
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
    """Test if a message is properly processed and a response is sent."""
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
    """Test if the connection is properly closed."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    class TransportMock:

        def __init__(self):
            pass

        @staticmethod
        def close(self):
            pass

    handler.transport = TransportMock()

    with patch.object(TransportMock, "close") as close_mock:
        handler.close()
        close_mock.assert_called_once()


def test_handler_process_request():
    """Check if request commands are correctly defined."""
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
    """Check if response commands are correctly defined."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    assert handler.process_response(b'ok', b"payload") == b"payload"

    with patch('wazuh.core.cluster.common.Handler.process_error_from_peer', return_value=b"payload"):
        assert handler.process_response(b"err", b"payload") == b"payload"

    assert handler.process_response(b"command", b"payload") == b"Unkown response command received: command"


def test_handler_echo():
    """Test if response command to 'echo' are defined."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    assert handler.echo(b"data") == (b"ok", b"data")


def test_handler_receive_file():
    """Test if a descriptor file is created for an incoming file."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    assert handler.receive_file(b"data") == (b"ok ", b"Ready to receive new file")
    assert "fd" in handler.in_file[b"data"]
    assert isinstance(handler.in_file[b"data"]["fd"], _io.BufferedWriter)
    assert "checksum" in handler.in_file[b"data"]
    assert isinstance(handler.in_file[b"data"]["checksum"], _hashlib.HASH)


def test_handler_update_file():
    """Test if a file's content is being updated."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with patch('builtins.open'):
        with open(os.path.join(os.getcwd(), "no_file.txt")) as f:
            handler.in_file = {b"filepath": {"fd": f, "checksum": hashlib.sha256()}}
            assert handler.update_file(b"filepath data") == (b"ok", b"File updated")


def test_handler_end_file():
    """Test if a file descriptor is closed and MD5 checked."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    class ChecksumMock:

        def __init__(self):
            pass

        @staticmethod
        def digest():
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
    """Test if a bytearray is created with the string size."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    reply, name = handler.receive_str(b"10")
    assert reply == b"ok"
    assert isinstance(name, bytes)
    assert isinstance(handler.in_str[list(handler.in_str.keys())[0]], cluster_common.InBuffer)


def test_handler_str_upd():
    """Test if a string content is updated."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with patch('wazuh.core.cluster.common.InBuffer.receive_data'):
        handler.in_str = {b"string_id": in_buffer}
        assert handler.str_upd(b"string_id data") == (b"ok", b"String updated")


def test_handler_process_error_str():
    """Test if an item is being deleted from self.in_str."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    # Test no conditioned return
    assert handler.process_error_str(b"120") == (b'ok', b'None')
    assert handler.in_str == {}

    # Test return inside loop and condition
    handler.in_str = {b"string_id": in_buffer}
    assert handler.process_error_str(b"2048") == (b'ok', b'string_id')
    assert handler.in_str == {}


def test_handler_process_unknown_cmd():
    """Test if a message is defined when an unknown command is received."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    assert handler.process_unknown_cmd(b"unknown") == (b'err', "unknown command 'b'unknown''".encode())


def test_handler_process_error_from_peer():
    """Test if errors in requests are properly handled."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    with patch('json.loads', return_value="some value"):
        assert handler.process_error_from_peer(b"data to decode") == "some value"

    assert isinstance(handler.process_error_from_peer(b"data to decode"), exception.WazuhClusterError)


def test_handler_setup_task_logger():
    """Test if a logger is being defined."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    class TaskLoggerMock:
        def __init__(self):
            pass

        @staticmethod
        def addFilter(info):
            pass

    with patch.object(logging.getLogger("wazuh"), "getChild", return_value=TaskLoggerMock()) as get_child_mock:
        with patch.object(TaskLoggerMock, "addFilter") as add_filter_mock:
            handler.setup_task_logger("task_tag")
            get_child_mock.assert_called_once_with("task_tag")
            add_filter_mock.assert_called_once()
            assert isinstance(handler.setup_task_logger("task_tag"), TaskLoggerMock)


# Test 'WazuhCommon' class methods

def test_wazuh_common_init():
    """Test the '__init__' method correct functioning."""

    wazuh_common_test = cluster_common.WazuhCommon()
    assert wazuh_common_test.sync_tasks == {}
    assert wazuh_common_test.logger_tag == ""


def test_wazuh_common_get_logger():
    """Check if a Logger object is properly returned."""

    with pytest.raises(NotImplementedError):
        wazuh_common.get_logger()


def test_wazuh_common_setup_receive_file():
    """Checkif ReceiveFileTask class is created and added to the task dictionary."""

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
        assert MyTaskMock().task_id in wazuh_common.sync_tasks
        assert isinstance(wazuh_common.sync_tasks[MyTaskMock().task_id], MyTaskMock)


@patch('wazuh.core.cluster.common.WazuhCommon')
@patch('logging.Logger')
def test_wazuh_common_end_receiving_file_ok(logger_mock, wazuh_common_mock):
    """Check if the full path to the received file is properly stored and availability is notified."""

    with patch('wazuh.core.cluster.common.ReceiveFileTask.set_up_coro'):
        with patch('asyncio.create_task'):
            file_task = cluster_common.ReceiveFileTask(wazuh_common_mock, logger_mock, b"task")

    wazuh_common.sync_tasks = {'task_ID': file_task}
    assert wazuh_common.end_receiving_file("task_ID filepath") == (b'ok', b'File correctly received')
    assert isinstance(wazuh_common.sync_tasks["task_ID"], cluster_common.ReceiveFileTask)


@patch('os.remove')
@patch('os.path.exists', return_value=True)
def test_wazuh_common_end_receiving_file_ko(path_exists_mock, os_remove_mock):
    """Test the 'end_receiving_file' correct functioning in a failure scenario."""

    with pytest.raises(exception.WazuhClusterError, match=r'.* 3027 .*'):
        wazuh_common.end_receiving_file("not_task_ID filepath")

    with patch('wazuh.core.cluster.common.WazuhCommon.get_logger'):
        with pytest.raises(exception.WazuhClusterError, match=r'.* 3027 .*'):
            os_remove_mock.side_effect = Exception
            wazuh_common.end_receiving_file("not_task_ID filepath")
            os_remove_mock.assert_called_once_with(Exception)


@patch('json.loads')
def test_wazuh_common_error_receiving_file_ok(json_loads_mock):
    """Check how error are handled by peer in the sent file process."""

    with patch('os.path.exists', return_value=True):
        with patch('os.remove'):
            # Test first condition and its nested condition
            assert wazuh_common.error_receiving_file("task_ID error_details") == (b'ok', b'Error received')

    # Test second condition
    with patch('wazuh.core.cluster.common.WazuhCommon.get_logger'):
        assert wazuh_common.error_receiving_file("not_task_ID error_details") == (b'ok', b'Error received')


def test_wazuh_common_error_receiving_file_ko():
    """Test the 'error_receiving_file' when an exception takes place."""

    with patch('json.loads'):
        with patch('os.path.exists', return_value=True):
            with patch('os.remove', side_effect=Exception):
                with patch('wazuh.core.cluster.common.WazuhCommon.get_logger'):
                    assert wazuh_common.error_receiving_file("task_ID error_details") == (b'ok', b'Error received')


def test_wazuh_common_get_node():
    """Check if it is possible to obtain basic information about the node."""

    class MockClass(cluster_common.WazuhCommon, cluster_common.Handler, abc.ABC):
        def __init__(self):
            super().__init__()

    class MockManager:
        def __init__(self):
            pass

        def get_node(self):
            pass

    mock_class = MockClass()
    mock_manager = MockManager()

    with patch('wazuh.core.cluster.common.Handler.get_manager', return_value=mock_manager) as manager_mock:
        mock_class.get_node()
        manager_mock.assert_called_once()


@patch.object(logging, "error")
@patch('asyncio.new_event_loop')
@patch('traceback.format_tb', return_value="traceback")
def test_asyncio_exception_handler(format_tb, mock_loop, mock_logging):
    """Test logger.error proper message."""

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


def test_wazuh_json_encoder_default():
    """Test if a special JSON encoder is defined for Wazuh."""

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
            super().__init__()
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
        assert wazuh_encoder.default(date) == {'__wazuh_datetime__': '2021-10-15T00:00:00'}

        # Test simple return
        with pytest.raises(TypeError):
            wazuh_encoder.default({"key": "value"})


def test_as_wazuh_object_ok():
    """Test the different outputs taking into account the input values."""

    # Test the first condition and nested if
    assert cluster_common.as_wazuh_object({"__callable__": {"__name__": "type", "__wazuh__": "version"}}) == "server"

    # Test the first condition and nested else
    assert isinstance(
        cluster_common.as_wazuh_object({"__callable__": {"__name__": "path", "__qualname__": "__loader__.value",
                                                         "__module__": "os"}}), str)

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
    """Test if the exceptions are correctly raised."""

    with pytest.raises(exception.WazuhInternalError, match=r'.* 1000 .*'):
        cluster_common.as_wazuh_object({"__callable__": {"__name__": "value", "__wazuh__": "value"}})
