# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import _hashlib
import _io
import abc
import asyncio
import hashlib
import json
import logging
import os
import sys
from contextvars import ContextVar
from datetime import datetime
from unittest.mock import patch, MagicMock, mock_open, call, ANY, AsyncMock

import cryptography
import pytest
from freezegun import freeze_time
from uvloop import EventLoopPolicy, new_event_loop, Loop

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
        from wazuh.core import common
        from wazuh.core.wdb import AsyncWazuhDBConnection

# Globals
cluster_items = {"etc/": {"permissions": "0o640", "source": "master", "files": ["client.keys"],
                          "description": "client keys file database"},
                 "intervals": {"worker": {"sync_integrity": 9, "sync_agent_info": 10, "sync_agent_groups": 10,
                                          "keep_alive": 60, "connection_retry": 10, "max_failed_keepalive_attempts": 2,
                                          "timeout_agent_groups": 40},
                               "master": {"recalculate_integrity": 8, "check_worker_lastkeepalive": 60,
                                          "max_allowed_time_without_keepalive": 120},
                               "communication": {"timeout_cluster_request": 20, "timeout_dapi_request": 200,
                                                 "timeout_receiving_file": 120, "max_zip_size": 1073741824,
                                                 "min_zip_size": 31457280, "zip_limit_tolerance": 0.2}
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
    event = asyncio.Event()
    with patch('asyncio.Event', return_value=event):
        response = cluster_common.Response()
        assert response.received_response == event
        assert response.content is None


@pytest.mark.asyncio
async def test_response_read():
    """Test for the 'read' method that belongs to the Response class. This method waits until a response is received."""

    with patch('asyncio.Event.wait') as wait_mock:
        response = cluster_common.Response()
        response.content = 'Testing'
        assert await response.read() == 'Testing'
        wait_mock.assert_called_once()


@pytest.mark.asyncio
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


# Test SendStringTask methods

@patch("asyncio.create_task")
@patch("wazuh.core.cluster.common.SendStringTask.set_up_coro")
def test_sst_init(setup_coro_mock, create_task_mock):
    """Test the '__init__' method."""

    class TaskMock:

        def __init__(self):
            pass

        def add_done_callback(self):
            pass

    create_task_mock.return_value = TaskMock()

    with patch.object(TaskMock, "add_done_callback") as done_callback_mock:
        sst_task = cluster_common.SendStringTask(wazuh_common=cluster_common.WazuhCommon(), logger='')
        assert sst_task.logger == ''
        assert sst_task.task in sst_task.tasks_hard_reference
        assert isinstance(sst_task.wazuh_common, cluster_common.WazuhCommon)
        setup_coro_mock.assert_called_once()
        done_callback_mock.assert_called_once()


@patch("asyncio.create_task")
@patch("wazuh.core.cluster.common.SendStringTask.set_up_coro")
def test_sst_done_callback(setup_coro_mock, create_task_mock):
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
        logger = logging.getLogger('wazuh')
        with patch.object(logger, "error") as logger_mock:
            sst_task = cluster_common.SendStringTask(wazuh_common=wazuh_common_mock, logger=logger)
            assert sst_task.task in sst_task.tasks_hard_reference
            sst_task.done_callback()
            logger_mock.assert_called_once_with(Exception)
            assert sst_task.task not in sst_task.tasks_hard_reference


# Test ReceiveStringTask methods

@patch("asyncio.create_task")
@patch("wazuh.core.cluster.common.ReceiveStringTask.set_up_coro")
def test_rst_init(setup_coro_mock, create_task_mock):
    """Test the '__init__' method."""

    class TaskMock:

        def __init__(self):
            pass

        def add_done_callback(self):
            pass

    create_task_mock.return_value = TaskMock()

    with patch.object(TaskMock, "add_done_callback") as done_callback_mock:
        string_task = cluster_common.ReceiveStringTask(wazuh_common=cluster_common.WazuhCommon(), logger='',
                                                       info_type='testing', task_id=b"010")
        assert isinstance(string_task.wazuh_common, cluster_common.WazuhCommon)
        setup_coro_mock.assert_called_once()
        done_callback_mock.assert_called_once()
        assert string_task.info_type == 'testing'
        assert string_task.task_id == b"010"
        assert isinstance(string_task.task, TaskMock)


@pytest.mark.asyncio
@patch('logging.Logger')
async def test_rst_str_method(logger_mock, event_loop):
    """Test the proper output of the '__str__' method."""
    async def coro(task_id: str, data: str):
        return ''

    def return_coro():
        return coro

    with patch('wazuh.core.cluster.common.ReceiveStringTask.set_up_coro', side_effect = return_coro) as setup_coro_mock:
        string_task = cluster_common.ReceiveStringTask(cluster_common.WazuhCommon(), '', b"task", logger_mock)
        assert isinstance(string_task.__str__(), str)
        assert string_task.__str__() == "task"
        await string_task.coro('task', 'data' )


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
        logger = logging.getLogger('wazuh')
        with patch.object(logger, "error") as logger_mock:
            string_task = cluster_common.ReceiveStringTask(wazuh_common=wazuh_common_mock, logger=logger,
                                                           info_type='agent-groups', task_id=b"010")
            string_task.done_callback()
            assert string_task.wazuh_common.in_str == {b"011": b"123456789"}
            assert string_task.wazuh_common.sync_tasks == {b"011": b"123456789"}
            logger_mock.assert_called_once_with(Exception, exc_info=False)


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
            logger_mock.assert_called_once_with(Exception, exc_info=False)


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
        assert handler.interrupted_tasks == set()
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


@patch('struct.pack', return_value=b"v1")
def test_handler_msg_build_ok(pack_mock):
    """Test if a message is being built with the right header and payload."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    # Test first if
    assert isinstance(handler.msg_build(b"command", 12345, b"data"), list)
    assert isinstance(handler.msg_build(b"command", 12345, b"data")[0], bytearray)

    # Test first else
    handler.header_len = 1
    handler.request_chunk = 20

    assert isinstance(handler.msg_build(b"command", 12345, b"000000000000000000000"), list)
    assert isinstance(handler.msg_build(b"command", 12345, b"data")[0], bytearray)

    assert pack_mock.call_count == 10


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
@patch('wazuh.core.cluster.common.Handler.next_counter', return_value=30)
@patch('wazuh.core.cluster.common.Handler.msg_build', return_value=["some", "messages"])
async def test_handler_send_request_ok(msg_build_mock, next_counter_mock, push_mock):
    """Test if a request is being properly sent."""

    async def delay():
        await asyncio.sleep(0.5)

    handler = cluster_common.Handler(fernet_key, cluster_items)

    with patch('wazuh.core.cluster.common.Response.read', return_value="some value") as read_mock:
        assert (await handler.send_request(b'some bytes', b'some data') == "some value")
        assert next_counter_mock.return_value not in handler.box
        read_mock.assert_awaited_once()

    handler.cluster_items['intervals']['communication']['timeout_cluster_request'] = 0.01
    with patch('wazuh.core.cluster.common.Response.read', side_effect=delay):
        with pytest.raises(exception.WazuhClusterError, match=r'\b3020\b'):
            await handler.send_request(b'some bytes', b'some data')
        read_mock.assert_awaited_once()
        assert handler.box[next_counter_mock.return_value] is None


    msg_build_mock.assert_called_with(b'some bytes', 30, b'some data')
    next_counter_mock.assert_called_with()

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
@patch('wazuh.core.cluster.common.Handler.send_request')
async def test_handler_get_chunks_in_task_id(send_request_mock):
    """Test if all chunks are collected from task_id."""

    class TaskMock:
        def __init__(self):
            self.payload = b'{"Objective": "fix_behavior"}'

    handler = cluster_common.Handler(fernet_key, cluster_items)
    handler.in_str[b'17'] = TaskMock()
    assert await handler.get_chunks_in_task_id(task_id=b'17', error_command=b'') == {"Objective": "fix_behavior"}

    # Test KeyError
    with pytest.raises(exception.WazuhClusterError, match='.* 3035 .*'):
        await handler.get_chunks_in_task_id(task_id=b'18', error_command=b'test_error')

    send_request_mock.assert_called_with(
        command=b'test_error', data=b'error while trying to access string under task_id b\'18\'.')

    # Test ValueError
    send_request_mock.reset_mock()
    handler.in_str[b'17'].payload = b'{"Objective": \'fix_behavior"}'
    with pytest.raises(exception.WazuhClusterError, match='.* 3036 .*'):
        await handler.get_chunks_in_task_id(task_id=b'17', error_command=b'test_error')

    send_request_mock.assert_called_with(
        command=b'test_error', data=b'error while trying to load JSON: Expecting value: line 1 column 15 (char 14)')


@pytest.mark.asyncio
@patch('wazuh.core.cluster.common.Handler.send_request')
async def test_handler_update_chunks_wdb(send_request_mock):
    """Test that the received chunks are sent correctly to wdb."""

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._debug = []
            self._debug2 = []
            self._error = []

        def debug(self, data):
            """Auxiliary method."""
            self._debug.append(data)

        def debug2(self, data):
            """Auxiliary method."""
            self._debug2.append(data)

        def error(self, data):
            """Auxiliary method."""
            self._error.append(data)

    class ServerMock:
        def __init__(self, task_pool):
            self.task_pool = task_pool

    logger = LoggerMock()
    handler = cluster_common.Handler(fernet_key, cluster_items)
    handler.server = ServerMock(None)

    with patch('wazuh.core.cluster.common.send_data_to_wdb', new_callable=AsyncMock) as send_data_to_wdb_mock:
        with patch.object(LoggerMock, "debug") as logger_debug_mock:
            with patch.object(LoggerMock, "debug2") as logger_debug2_mock:
                with patch.object(LoggerMock, "error") as logger_error_mock:
                    send_data_to_wdb_mock.return_value = {
                        'total_updated': 0, 'errors_per_folder': {'key': 'value'}, 'generic_errors': ['ERR'],
                        'updated_chunks': 2, 'time_spent': 6,
                        'error_messages': {'chunks': [[0, 0], [1, 1]], 'others': ['other1', 'other2']}}
                    assert await handler.update_chunks_wdb(
                        data={'chunks': [0, 1, 2, 3, 4]}, info_type='agent-groups',
                        logger=logger, error_command=b'ERROR', timeout=10) == {'error_messages': [0, 1],
                                                                               'errors_per_folder': {'key': 'value'},
                                                                               'generic_errors': ['ERR'],
                                                                               'time_spent': 6,
                                                                               'total_updated': 0, 'updated_chunks': 2}
                    logger_debug_mock.assert_has_calls([call('2/5 chunks updated in wazuh-db in 6.000s.')])
                    logger_debug2_mock.assert_has_calls([call('Chunk 1/5: 0'), call('Chunk 2/5: 1')])
                    logger_error_mock.assert_has_calls([call('other1'), call('other2'),
                                                        call('Wazuh-db response for chunk 1/5 was not "ok": 0'),
                                                        call('Wazuh-db response for chunk 2/5 was not "ok": 1')])

    # Test Exception
    send_request_mock.reset_mock()
    error_message = 'error'
    with patch('wazuh.core.cluster.common.send_data_to_wdb', side_effect=Exception(error_message)):
        with pytest.raises(exception.WazuhClusterError,
                        match=r'.*Error 3037 - Error while processing Agent-info chunks: .*'):
            await handler.update_chunks_wdb(data={'chunks': [0, 1, 2, 3, 4]}, info_type='info',
                                            logger=logger, error_command=b'ERROR', timeout=10)

    send_request_mock.assert_has_calls(
        [call(command=b'ERROR',
              data=f'error processing info chunks in process pool: {error_message}'.encode())])


@pytest.mark.asyncio
@patch('os.path.exists', return_value=True)
@patch('builtins.open', mock_open(read_data=b'chunks'))
@patch('wazuh.core.cluster.common.Handler.send_request', return_value=b'some data')
async def test_handler_send_file_ok(send_request_mock, os_path_exists_mock):
    """Test if a file is being correctly sent to peer."""

    class MockHash:
        """Mock class."""

        def update(self, chunk=""):
            """Auxiliary method."""
            pass

        @staticmethod
        def digest():
            """Auxiliary method."""
            return b""

    handler = cluster_common.Handler(fernet_key, cluster_items)
    handler.request_chunk = 17
    handler.interrupted_tasks.add(b'abcd')

    with patch('hashlib.sha256', return_value=MockHash()):
        assert (await handler.send_file('some_file.txt', task_id=b'abcd') == 3)
        send_request_mock.assert_has_calls([call(command=b'file_upd', data=b'some_file.txt chu'),
                                            call(command=b'file_end', data=b'some_file.txt ')])
        assert send_request_mock.call_count == 3
        os_path_exists_mock.assert_called_once_with('some_file.txt')


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

    with patch('wazuh.core.cluster.common.Handler.send_request', side_effect=exception.WazuhClusterError(3020)):
        with patch.object(logging.getLogger("wazuh"), "error") as logger_mock:
            assert exception.WazuhClusterError(3020).message.encode() in await handler.send_string(b"something")
            logger_mock.assert_called_once_with(
                f'There was an error while trying to send a string: Error 3020 - Timeout sending request',
                exc_info=False)


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
@pytest.mark.parametrize('exception, expected_error', [
    (exception.WazuhException(1001), exception.WazuhException(1001)),
    (exception.WazuhClusterError(3020), None),
    (Exception('Test'), exception.WazuhClusterError(1000, extra_message='Test'))
])
async def test_handler_forward_sendsync_response_ko(exception, expected_error):
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
        with patch.object(mock_manager.local_server, "send_request", side_effect=exception):
            with patch.object(logging.getLogger('wazuh'), "error") as logger_mock:
                with patch('wazuh.core.cluster.common.Handler.send_request',
                           return_value="some value") as send_request_mock:
                    await handler.forward_sendsync_response(b"client string_id")
                    assert handler.in_str == {b'other_string': 'some value'}

                    if expected_error:
                        logger_mock.assert_called_once_with(f"Error sending sendsync response to local client: "
                                                            f"{str(exception)}")
                        send_request_mock.assert_called_once_with(
                            b'sendsync_err',
                            json.dumps(expected_error, cls=cluster_common.WazuhJSONEncoder).encode()
                        )
                    else:
                        logger_mock.assert_not_called()


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
    with patch('wazuh.core.cluster.common.Handler.cancel_task') as cancel_task_mock:
        handler.process_request(b"cancel_task", b"data")
        cancel_task_mock.assert_called_once_with(b"data")
    with patch('wazuh.core.cluster.common.Handler.process_dapi_error') as process_dapi_err_mock:
        handler.process_request(b"dapi_err", b"dapi_client error_msg")
        process_dapi_err_mock.assert_called_once_with(b"dapi_client error_msg")
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


@pytest.mark.parametrize('task_name', [
    'abcd', 'None'
])
@patch('json.loads')
def test_handler_cancel_task(json_loads_mock, task_name):
    """Test if task_id is added to handler.interrupted_tasks when cancel_task() is executed."""
    handler = cluster_common.Handler(fernet_key, cluster_items)

    assert handler.cancel_task(f'{task_name} error_details'.encode()) == (b'ok', b'Request received correctly')
    json_loads_mock.assert_called_once_with(b'error_details', object_hook=ANY)
    if task_name != 'None':
        assert b'abcd' in handler.interrupted_tasks
    else:
        assert b'abcd' not in handler.interrupted_tasks


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


def test_handler_process_dapi_error():
    """Test if 'dapi_err' command is properly handled in 'process_dapi_error'."""

    handler = cluster_common.Handler(fernet_key, cluster_items)

    class ClientsMock:
        """Auxiliary class."""

        def send_request(self, command, error_msg):
            pass

    class LocalServerDapiMock:
        """Auxiliary class."""

        def __init__(self):
            self.clients = {"dapi_client": ClientsMock()}

    class ManagerMock:
        """Auxiliary class."""

        def __init__(self):
            self.local_server = LocalServerDapiMock()

    with patch("asyncio.create_task", return_value=b"ok") as create_task_mock:
        handler.server = ManagerMock()
        with patch.object(ClientsMock, "send_request") as send_request_mock:
            handler.process_dapi_error(b"dapi_client error_msg")
            send_request_mock.assert_called_once_with(b"dapi_err", b"error_msg")
            create_task_mock.assert_called_once()


def test_handler_process_dapi_error_ko():
    """Test the correct exception raise at method 'process_dapi_error'."""

    class ClientsMock:
        """Auxiliary class."""

        def send_request(self, command, error_msg):
            pass

    class LocalServerDapiMock:
        """Auxiliary class."""

        def __init__(self):
            self.clients = {"not_data": ClientsMock()}

    class ManagerMock:
        """Auxiliary class."""

        def __init__(self):
            self.local_server = LocalServerDapiMock()

    handler = cluster_common.Handler(fernet_key, cluster_items)
    with pytest.raises(exception.WazuhClusterError, match=r".* 3032 .*"):
        handler.server = ManagerMock()
        handler.process_dapi_error(data=b"data 2")

    with pytest.raises(exception.WazuhClusterError, match=r".* 3025 .*"):
        with patch("asyncio.create_task", side_effect=exception.WazuhClusterError(1001)):
            handler.server = ManagerMock()
            handler.server.local_server.clients = {"data": ClientsMock()}
            handler.process_dapi_error(data=b"data 2")


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


@pytest.mark.asyncio
async def test_handler_wait_for_file():
    """Check if wait_for is called with expected parameters.

       The implementation is complex because asyncio.wait_for is patched.
       Handler.wait_for_file and and unlocking coroutine are run using asyncio.gather
       The unlocking coroutine waits 0.5 seconds, while the timeout is set to 10 seconds
       The test must not raise any exception.
       '"""

    async def unlock_file(event: asyncio.Event):
        await asyncio.sleep(0.5)
        event.set()

    file_event = asyncio.Event()
    handler = cluster_common.Handler(fernet_key, cluster_items)
    handler.cluster_items['intervals']['communication']['timeout_receiving_file'] = 10
    await asyncio.gather(handler.wait_for_file(file_event, 'test'), unlock_file(file_event))

@pytest.mark.asyncio
@patch('wazuh.core.cluster.common.Handler.send_request')
async def test_handler_wait_for_file_ko(send_request_mock):
    """Check if expected exception is raised.
        Condition 1: when event.wait() exceeds the timeout, WazuhClusterError 3039 is raised
        Condition 2: when any other exception occurs, WazuhClusterError 3040  is raised"""

    async def delay():
        await asyncio.sleep(0.5)

    send_request_mock.return_value = ''
    handler = cluster_common.Handler(fernet_key, cluster_items)
    handler.cluster_items['intervals']['communication']['timeout_receiving_file'] = 0.4
    file_event = AsyncMock()
    with pytest.raises(exception.WazuhClusterError, match=r'.* 3039 .*'):
        with patch.object(file_event, 'wait', side_effect = delay):
            await handler.wait_for_file(file_event, 'test')
    send_request_mock.assert_called_once_with(command=b'cancel_task', data=ANY)

    with pytest.raises(exception.WazuhClusterError, match=r".* 3040 .*"):
        with patch.object(file_event, 'wait', side_effect = Exception('any')):
            await handler.wait_for_file(file_event, "task_id")
    send_request_mock.assert_called_with(command=b'cancel_task', data=ANY)


# Test 'WazuhCommon' class methods

def test_wazuh_common_init():
    """Test the '__init__' method correct functioning."""

    wazuh_common_test = cluster_common.WazuhCommon()
    assert wazuh_common_test.sync_tasks == {}


@pytest.mark.asyncio
@patch("wazuh.core.cluster.common.AsyncWazuhDBConnection", return_value=AsyncMock())
async def test_wazuh_common_recalculate_group_hash(asyncwazuhdbconnection_mock):
    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._debug = []

        def debug(self, data):
            """Auxiliary method."""
            self._debug.append(data)

    logger = LoggerMock()
    await wazuh_common.recalculate_group_hash(logger)
    assert logger._debug == ['Recalculating agent-group hash.']


@pytest.mark.asyncio
@patch("wazuh.core.cluster.common.AsyncWazuhDBConnection")
async def test_wazuh_common_recalculate_group_hash_ko(asyncwazuhdbconnection_mock):
    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._warning = []
            self._debug = []

        def debug(self, data):
            """Auxiliary method."""
            self._debug.append(data)

        def warning(self, data):
            """Auxiliary method."""
            self._warning.append(data)

    logger = LoggerMock()
    asyncwazuhdbconnection_mock.side_effect = [exception.WazuhInternalError(2007), exception.WazuhError(2003)]

    await wazuh_common.recalculate_group_hash(logger)
    assert logger._debug == ['Recalculating agent-group hash.']
    assert logger._warning == ['Error 2007 executing recalculate agent-group hash command: '
                               'Error retrieving data from Wazuh DB']

    logger = LoggerMock()
    await wazuh_common.recalculate_group_hash(logger)
    assert logger._debug == ['Recalculating agent-group hash.']
    assert logger._warning == ['Error 2003 executing recalculate agent-group hash command: Error in wazuhdb request']

def test_wazuh_common_get_logger():
    """Check if a Logger object is properly returned."""

    with pytest.raises(NotImplementedError):
        wazuh_common.get_logger()


def test_wazuh_common_setup_send_info():
    """Check if SendTaskClass class is created and returned."""

    class MyTaskMock:

        def __init__(self) -> None:
            self.task_id = "key"

    my_task = MyTaskMock()
    mock_object = MagicMock(return_value=my_task)

    with patch('wazuh.core.cluster.common.WazuhCommon.get_logger'):
        first_output, second_output = wazuh_common.setup_send_info(mock_object)
        assert first_output == b'ok'
        assert isinstance(second_output, bytes)


def test_wazuh_common_setup_receive_file():
    """Check if ReceiveFileTask class is created and added to the task dictionary."""

    class MyTaskMock:

        def __init__(self) -> None:
            self.task_id = "key"

    my_task = MyTaskMock()
    mock_object = MagicMock(return_value=my_task)

    with patch('wazuh.core.cluster.common.WazuhCommon.get_logger'):
        first_output, second_output = wazuh_common.setup_receive_file(mock_object)
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
    assert os_remove_mock.call_count == 2


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


# Test SyncWazuhdb class

def test_sync_wazuh_db_init():
    """Test the '__init__' method from the SyncWazuhdb class."""

    sync_wazuh_db = cluster_common.SyncWazuhdb(
        manager=cluster_common.Handler(fernet_key, cluster_items), logger=logging.getLogger("wazuh"), cmd=b"cmd",
        data_retriever=None, get_data_command="get_command", set_data_command="set_command", pivot_key=None)

    assert sync_wazuh_db.get_data_command == "get_command"
    assert sync_wazuh_db.set_data_command == "set_command"
    assert sync_wazuh_db.data_retriever is None


@pytest.mark.asyncio
@patch("wazuh.core.wdb.socket.socket")
async def test_sync_wazuh_db_retrieve_information(socket_mock):
    """Check the proper functionality of the function in charge of
    obtaining the information from the database of the manager nodes."""
    counter = 0

    def data_generator(command):
        nonlocal counter
        counter += 1
        if counter < 3:
            return 'due', {'id': counter}
        else:
            return 'ok', {'id': counter}

    wdb_conn = AsyncWazuhDBConnection()
    logger = logging.getLogger("wazuh")
    handler = cluster_common.Handler(fernet_key, cluster_items)
    sync_object = cluster_common.SyncWazuhdb(manager=handler, logger=logger, cmd=b'syn_a_w_m',
                                             data_retriever=wdb_conn.run_wdb_command,
                                             get_data_command='global sync-agent-info-get ',
                                             set_data_command='global sync-agent-info-set')

    with patch.object(sync_object, 'data_retriever', side_effect=data_generator):
        assert await sync_object.retrieve_information() == [{'id': 1}, {'id': 2}, {'id': 3}]

    sync_object = cluster_common.SyncWazuhdb(manager=handler, logger=logger, cmd=b'syn_a_w_m',
                                             data_retriever=wdb_conn.run_wdb_command,
                                             get_data_command='global sync-agent-info-get ', get_payload={'last_id': 0},
                                             set_data_command='global sync-agent-info-set', pivot_key='last_id')

    with patch.object(sync_object, 'data_retriever', return_value=('ok', '[{"data": [{"id": 45}]}]')):
        assert await sync_object.retrieve_information() == ['[{"data": [{"id": 45}]}]']
        assert sync_object.get_payload == {'last_id': 45}

    # data_retriever returns a JSON that does not follow the pivoting scheme
    with patch.object(sync_object, 'data_retriever', return_value=('ok', '[{"data": {"id": 45}}]')):
        assert await sync_object.retrieve_information() == ['[{"data": {"id": 45}}]']
        assert sync_object.get_payload == {'last_id': 0}

    # data_retriever returns a JSON that does not follow the pivoting scheme
    with patch.object(sync_object, 'data_retriever', side_effect=exception.WazuhException(1000)):
        with patch.object(sync_object.logger, 'error') as logger_error_mock:
            assert await sync_object.retrieve_information() == []
            logger_error_mock.assert_called_with(
                'Could not obtain data from wazuh-db: Error 1000 - Wazuh Internal Error')


@patch('wazuh.core.wdb_http.WazuhDBHTTPClient')
async def test_sync_wazuh_db_retrieve_agents_information(wdb_http_client_mock):
    """Validate that the `retrieve_agents_information` method works as expected."""
    logger = logging.getLogger('wazuh')
    handler = cluster_common.Handler(fernet_key, cluster_items)
    sync_object = cluster_common.SyncWazuhdb(manager=handler, logger=logger, cmd=b'syn_a_w_m',
                                             data_retriever=None,
                                             get_data_command='global sync-agent-info-get ',
                                             set_data_command='global sync-agent-info-set')

    agents_info = {'id': 1, 'name': 'test'}
    wdb_http_client_mock.return_value.close = AsyncMock()
    get_agents_sync_mock = AsyncMock(return_value=agents_info)
    wdb_http_client_mock.return_value.get_agents_sync = get_agents_sync_mock
    
    assert await sync_object.retrieve_agents_information() == {'id': 1, 'name': 'test'}


async def test_sync_wazuh_db_retrieve_agents_information_ko():
    """Validate that the `retrieve_agents_information` method handles exceptions successfully."""
    logger = logging.getLogger('wazuh')
    handler = cluster_common.Handler(fernet_key, cluster_items)
    sync_object = cluster_common.SyncWazuhdb(manager=handler, logger=logger, cmd=b'syn_a_w_m',
                                             data_retriever=None,
                                             get_data_command='global sync-agent-info-get ',
                                             set_data_command='global sync-agent-info-set')
    
    with patch('wazuh.core.wdb_http.WazuhDBHTTPClient', side_effect=exception.WazuhException(1000)):
        with patch.object(sync_object.logger, 'error') as logger_error_mock:
            assert await sync_object.retrieve_agents_information() is None
            logger_error_mock.assert_called_with(
                'Could not obtain data from wazuh-db: Error 1000 - Wazuh Internal Error')


@pytest.mark.asyncio
@freeze_time('1970-01-01')
@patch("json.dumps", return_value="")
@patch('wazuh.core.cluster.common.time.perf_counter', return_value=0)
async def test_sync_wazuh_db_sync_ok(perf_counter_mock, json_dumps_mock):
    """Check if the information is being properly sent to the master/worker node."""

    sync_wazuh_db = cluster_common.SyncWazuhdb(
        manager=cluster_common.Handler(fernet_key, cluster_items), logger=logging.getLogger("wazuh"), cmd=b"cmd",
        data_retriever=None, get_data_command="get_command", set_data_command="set_command", pivot_key=None)

    # Test try and if
    with patch.object(sync_wazuh_db.logger, "debug") as logger_debug_mock:
        with patch("wazuh.core.cluster.common.Handler.send_string", return_value=b"OK") as send_string_mock:
            with patch("wazuh.core.cluster.common.Handler.send_request",
                       side_effect=None) as send_request_mock:
                assert await sync_wazuh_db.sync(start_time=10, chunks=['a', 'b']) is True
                send_request_mock.assert_called_once_with(command=b"cmd", data=b"OK")
                json_dumps_mock.assert_called_with({'set_data_command': 'set_command',
                                                    'payload': {}, 'chunks': ['a', 'b']})
                logger_debug_mock.assert_has_calls([call(f"Sending chunks.")])

            send_string_mock.assert_called_with(b"")

    # Test else
    with patch.object(sync_wazuh_db.logger, "info") as logger_info_mock:
        assert await sync_wazuh_db.sync(start_time=-10, chunks=[]) is True
        logger_info_mock.assert_called_once_with(f"Finished in 10.000s. Updated 0 chunks.")

    # Test except
    with patch("wazuh.core.cluster.common.Handler.send_string", return_value=b'Error 1'):
        sync_wazuh_db.server = cluster_common.Handler(fernet_key, cluster_items)
        with pytest.raises(exception.WazuhClusterError, match=r".* 3016 .*"):
            await sync_wazuh_db.sync(start_time=10, chunks=['a'])


@patch("json.loads", return_value={"updated_chunks": 10, "error_messages": None})
@patch('wazuh.core.cluster.common.time.perf_counter', return_value=0)
def test_end_sending_agent_information(perf_counter_mock, json_loads_mock):
    """Check the correct output message when a command "syn_m_a_e", "syn_m_g_e" or "syn_w_g_e" takes place."""

    class get_utc_now_mock:
        def __init__(self):
            pass

        def timestamp(self):
            return 0

    logger = logging.getLogger('testing')
    with patch('wazuh.core.cluster.common.utils.get_utc_now', side_effect=get_utc_now_mock):
        with patch.object(logger, "info") as logger_info_mock:
            assert cluster_common.end_sending_agent_information(
                logger,
                datetime.fromtimestamp(0),
                "response"
                ) == (b'ok', b'Thanks')
            json_loads_mock.assert_called_once_with("response")
            logger_info_mock.assert_called_once_with("Finished in 0.000s. Updated 10 chunks.")

        with patch.object(logger, "error") as logger_error_mock:
            json_loads_mock.return_value = {"updated_chunks": 10, "error_messages": "error"}
            assert cluster_common.end_sending_agent_information(
                logger,
                datetime.fromtimestamp(0),
                "response"
                ) == (b'ok', b'Thanks')
            logger_error_mock.assert_called_once_with(
                "Finished in 0.000s. Updated 10 chunks. There were 5 chunks with errors: error")


def test_error_receiving_agent_information():
    """Check the correct output message when a command
    "syn_m_a_err", "syn_m_g_err", "syn_w_g_err" or "syn_w_g_err" takes place."""

    logger = logging.getLogger('testing')
    with patch.object(logger, "error") as logger_error_mock:
        assert cluster_common.error_receiving_agent_information(logger, "response", "info") == (b'ok', b'Thanks')
        logger_error_mock.assert_called_once_with("There was an error while processing info on the peer: response")


@patch("wazuh.core.cluster.common.WazuhDBConnection")
async def test_send_data_to_wdb(WazuhDBConnection_mock):
    """Check if the data chunks are being properly forward to the Wazuh-db socket."""

    class MockWazuhDBConnection:
        """Auxiliary class."""

        def __init__(self):
            self.exceptions = 0

        def send(self, data, raw):
            """Auxiliary method."""
            if self.exceptions == 0:
                raise TimeoutError
            elif self.exceptions == 1:
                return ''
            elif self.exceptions == 2:
                raise Exception('Cannot execute Global database query; FOREIGN KEY constraint failed')
            else:
                raise Exception

        def close(self):
            """Auxiliary method."""
            pass

    WazuhDBConnection_mock.return_value = MockWazuhDBConnection()
    chunks = ['[{"data": "1chunk"}]', '[{"data": "2chunk"}]']

    result = await cluster_common.send_data_to_wdb(data={'chunks': ['[{"data": ""}]'], 'payload': {}, 
                                                         'set_data_command': ''}, timeout=15, info_type='agent-groups')
    assert result['error_messages']['others'] == ['Timeout while processing agent-groups chunks.']

    WazuhDBConnection_mock.return_value.exceptions += 1
    result = await cluster_common.send_data_to_wdb(data={'chunks': chunks, 
                                                         'payload': {}, 'set_data_command': ''}, 
                                                         timeout=15, info_type='agent-groups')
    assert result['updated_chunks'] == 2

    WazuhDBConnection_mock.return_value.exceptions += 1
    result = await cluster_common.send_data_to_wdb(data={'chunks': chunks, 'set_data_command': ''},
                                             timeout=15, info_type='agent-groups')
    assert result['updated_chunks'] == 0

    WazuhDBConnection_mock.return_value.exceptions += 1
    result = await cluster_common.send_data_to_wdb(data={'chunks': chunks, 'payload': {}, 'set_data_command': ''},
                                             timeout=15, info_type='agent-groups')
    assert result['error_messages']['chunks'] == [(0, ''), (1, '')]

    with patch('wazuh.core.cluster.master.utils.Timeout', side_effect=Exception):
        result = await cluster_common.send_data_to_wdb(data={'chunks': chunks, 'set_data_command': ''},
                                                 timeout=15, info_type='agent-groups')
        assert result['error_messages']['others'] == ['Error while processing agent-groups chunks: ']


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


@patch('wazuh.core.common.os.chmod')
@patch('wazuh.core.common.os.chown')
@patch('wazuh.core.common.wazuh_gid', return_value=0)
@patch('wazuh.core.common.wazuh_uid', return_value=0)
@patch('wazuh.core.common.INSTALLATION_UID_PATH', os.path.join('/tmp', 'installation_uid'))
def test_wazuh_json_encoder_default(mock_chmod, mock_chown, mock_gid, mock_uid):
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
        assert isinstance(wazuh_encoder.default(exception.WazuhException(3009)), dict)
        assert wazuh_encoder.default(exception.WazuhException(3009)) == \
               {'__wazuh_exception__': {'__class__': 'WazuhException',
                                        '__object__': {'type': 'about:blank', 'title': 'WazuhException', 'code': 3009,
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

        # Test fifth condition
        exc = ValueError('test')
        assert isinstance(wazuh_encoder.default(exc), dict)
        assert wazuh_encoder.default(exc) == {'__unhandled_exc__': {'__class__': 'ValueError',
                                                                    '__args__': ('test',)}}

        # Test simple return
        with pytest.raises(TypeError):
            wazuh_encoder.default({"key": "value"})


@patch('wazuh.core.common.os.chmod')
@patch('wazuh.core.common.os.chown')
@patch('wazuh.core.common.wazuh_gid', return_value=0)
@patch('wazuh.core.common.wazuh_uid', return_value=0)
@patch('wazuh.core.common.INSTALLATION_UID_PATH', os.path.join('/tmp', 'installation_uid'))
def test_as_wazuh_object_ok(mock_chmod, mock_chown, mock_gid, mock_uid):
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

    # Test the fifth condition
    result = cluster_common.as_wazuh_object({'__unhandled_exc__': {'__class__': 'ValueError',
                                                                   '__args__': ('test',)}})
    assert result == {"ValueError": ["test"]}

    result = cluster_common.as_wazuh_object({'__unhandled_exc__': {'__class__': 'exit',
                                                                   '__args__': []}})
    assert result == {"exit": []}

    # No condition fulfilled
    assert isinstance(cluster_common.as_wazuh_object({"__wazuh_datetime_bad__": "2021-10-14"}), dict)
    assert cluster_common.as_wazuh_object({"__wazuh_datetime_bad__": "2021-10-14"}) == \
           {"__wazuh_datetime_bad__": "2021-10-14"}


@patch('wazuh.core.common.os.chmod')
@patch('wazuh.core.common.os.chown')
@patch('wazuh.core.common.wazuh_gid', return_value=0)
@patch('wazuh.core.common.wazuh_uid', return_value=0)
@patch('wazuh.core.common.INSTALLATION_UID_PATH', os.path.join('/tmp', 'installation_uid'))
def test_as_wazuh_object_ko(mock_chmod, mock_chown, mock_gid, mock_uid):
    """Test if the exceptions are correctly raised."""

    with pytest.raises(exception.WazuhInternalError, match=r'.* 1000 .*'):
        cluster_common.as_wazuh_object({"__callable__": {"__name__": "value", "__wazuh__": "value"}})


def get_handler():
    """Return a Handler object. This is an auxiliary method."""
    return cluster_common.Handler(fernet_key=fernet_key, cluster_items=cluster_items, logger=logging.getLogger("wazuh"))


# Test SyncTask class methods

def test_sync_task_init():
    """Test '__init__' method from the SyncTask class."""
    sync_task = cluster_common.SyncTask(b"cmd", logging.getLogger("wazuh"), get_handler())

    assert sync_task.cmd == b"cmd"
    assert sync_task.logger == logging.getLogger("wazuh")
    assert isinstance(sync_task.server, cluster_common.Handler)


@pytest.mark.asyncio
@patch('wazuh.core.cluster.common.Handler.send_request', side_effect=Exception())
async def test_sync_task_request_permission(send_request_mock):
    """Check if a True value is returned once a permission to start synchronization is granted or a False when it
    is not."""
    sync_task = cluster_common.SyncTask(b"cmd", logging.getLogger("wazuh"), get_handler())

    # Test first condition
    with patch.object(logging.getLogger("wazuh"), "error") as logger_mock:
        assert await sync_task.request_permission() is False
        send_request_mock.assert_called_with(command=b"cmd" + b"_p", data=b"")
        logger_mock.assert_called_once_with(f"Error asking for permission: {Exception()}")

    with patch.object(logging.getLogger("wazuh"), "debug") as logger_mock:
        # Test second condition
        send_request_mock.side_effect = None
        send_request_mock.return_value = b"True"
        assert await sync_task.request_permission() is True
        send_request_mock.assert_called_with(command=b"cmd" + b"_p", data=b"")
        logger_mock.assert_called_once_with("Permission to synchronize granted.")

        # Test third condition
        send_request_mock.return_value = b"False"
        assert await sync_task.request_permission() is False
        send_request_mock.assert_called_with(command=b"cmd" + b"_p", data=b"")
        logger_mock.assert_called_with("Master didn't grant permission to start a new synchronization: b'False'")


@pytest.mark.asyncio
async def test_sync_task_sync():
    """Test if an Exception is raised when an error takes place."""
    sync_task = cluster_common.SyncTask(b"cmd", logging.getLogger("wazuh"), get_handler())

    with pytest.raises(NotImplementedError):
        await sync_task.sync()


# Test SyncFiles class methods

@pytest.mark.asyncio
@patch("json.dumps", return_value='')
@patch("os.path.relpath", return_value="path")
@patch("os.unlink", return_value="unlinked path")
@patch("wazuh.core.cluster.cluster.compress_files", return_value=("files/path/", {}))
@patch("wazuh.core.cluster.utils.log_subprocess_execution")
async def test_sync_files_sync_ok(log_subprocess_mock, compress_files_mock, unlink_mock, relpath_mock, json_dumps_mock):
    """Check if the methods to synchronize files are defined."""
    files_to_sync = {"path1": "metadata1"}
    files_metadata = {"path2": "metadata2"}

    class WorkerMock:
        """Class used to mock the self.worker value and enter the conditions inside the try."""

        def __init__(self):
            self.name = "Testing"
            self.count = 1
            self.loop = loop
            self.current_zip_limit = cluster_items['intervals']['communication']['max_zip_size']
            self.interrupted_tasks = {b'OK', b'abcd'}
            self.cluster_items = cluster_items

        async def send_request(self, command, data):
            """Decide with will be the right output depending on the scenario."""
            if command == b"cmd" and data == b"" and self.count == 1:
                raise exception.WazuhClusterError(3020, extra_message=command.decode())
            elif command == b"cmd" and data == b"" and self.count == 2:
                return b"OK"
            elif command == b"cmd_e" and b"OK path" and self.count == 2:
                raise Exception()
            elif command == b"cmd" and data == b"" and self.count == 3:
                return b"OK"
            elif command == b"cmd_e" and b"OK path" and self.count == 3:
                raise exception.WazuhClusterError(3016, extra_message=command.decode())
            elif command == b"cmd" and data == b"" and self.count == 4:
                return b"OK"
            elif command == b"cmd_e" and b"OK path" and self.count == 4:
                return b"OK"

        async def send_file(self, filename, task_id):
            """Auxiliary method."""
            pass

    worker_mock = WorkerMock()
    sync_files = cluster_common.SyncFiles(b"cmd", logging.getLogger("wazuh"), worker_mock)

    # Test second condition
    with patch.object(logging.getLogger("wazuh"), "error") as logger_mock:
        await sync_files.sync(files_to_sync, files_metadata, 1, task_pool=None)
        log_subprocess_mock.assert_called()
        json_dumps_mock.assert_called_once_with(
            exception.WazuhClusterError(code=3020, extra_message="cmd"),
            cls=cluster_common.WazuhJSONEncoder)
        logger_mock.assert_called_once_with("Error sending zip file: Error 3020 - Timeout sending request: cmd")

    worker_mock.count = 2
    with patch.object(WorkerMock, "send_file", return_value=1000) as send_file_mock:
        # Test if present in try and second exception
        with patch.object(logging.getLogger("wazuh"), "debug") as logger_debug_mock:
            with patch.object(logging.getLogger("wazuh"), "error") as logger_error_mock:
                await sync_files.sync(files_to_sync, files_metadata, 1, task_pool=None)
                send_file_mock.assert_called_once_with('files/path/', b'OK')
                logger_debug_mock.assert_has_calls([call(
                    f"Compressing {'files and ' if files_to_sync else ''}'files_metadata.json' of 1 files."),
                    call("Sending zip file."), call("Zip file sent."), call("Decreasing sync size limit to 30.00 MB.")])
                log_subprocess_mock.assert_called()
                logger_error_mock.assert_called_once_with("Error sending zip file: ")
                compress_files_mock.assert_has_calls([call('Testing', {'path1': 'metadata1'},
                                                           {'path2': 'metadata2'}, None)] * 2)
                unlink_mock.assert_called_with("files/path/")
                relpath_mock.assert_called_once_with('files/path/', common.WAZUH_PATH)
                assert json_dumps_mock.call_count == 2

                # Reset all mocks
                all_mocks = [send_file_mock, logger_debug_mock, logger_error_mock, compress_files_mock, unlink_mock,
                             relpath_mock, json_dumps_mock]
                for mock in all_mocks:
                    mock.reset_mock()

                # Test elif present in try and first exception
                worker_mock.count = 3
                await sync_files.sync(files_to_sync, files_metadata, 1, task_pool=None)
                send_file_mock.assert_called_once_with('files/path/', b'OK')
                logger_debug_mock.assert_has_calls([call(
                    f"Compressing {'files and ' if files_to_sync else ''}'files_metadata.json' of 1 files."),
                    call("Sending zip file."), call("Zip file sent."), call('Increasing sync size limit to 37.50 MB.')])
                log_subprocess_mock.assert_called()
                logger_error_mock.assert_called_once_with(
                    f"Error sending zip file: {exception.WazuhException(3016, 'cmd_e')}")
                compress_files_mock.assert_called_once_with('Testing', {'path1': 'metadata1'},
                                                            {'path2': 'metadata2'}, None)
                unlink_mock.assert_called_once_with("files/path/")
                relpath_mock.assert_called_once_with('files/path/', common.WAZUH_PATH)
                json_dumps_mock.assert_called_once()

                # Reset all mocks
                all_mocks = [send_file_mock, logger_debug_mock, logger_error_mock, compress_files_mock, unlink_mock,
                             relpath_mock, json_dumps_mock]
                for mock in all_mocks:
                    mock.reset_mock()

            # Test return
            worker_mock.count = 4
            await sync_files.sync(files_to_sync, files_metadata, 1, task_pool=None)
            send_file_mock.assert_called_once_with('files/path/', b'OK')
            logger_debug_mock.assert_has_calls([call(
                f"Compressing {'files and ' if files_to_sync else ''}'files_metadata.json' of 1 files."),
                call("Sending zip file."), call("Zip file sent."), call("Increasing sync size limit to 46.88 MB.")])
            log_subprocess_mock.assert_called()
            compress_files_mock.assert_called_once_with('Testing', {'path1': 'metadata1'}, {'path2': 'metadata2'}, None)
            unlink_mock.assert_called_once_with("files/path/")
            relpath_mock.assert_called_once_with('files/path/', common.WAZUH_PATH)

            assert worker_mock.interrupted_tasks == {b'abcd'}


@pytest.mark.asyncio
@patch("wazuh.core.cluster.common.Handler.send_request", side_effect=Exception())
async def test_sync_files_sync_ko(send_request_mock):
    """Test if the right exceptions are being risen when necessary."""
    files_to_sync = {"path1": "metadata1"}
    files_metadata = {"path2": "metadata2"}
    handler = get_handler()
    handler.loop = None
    handler.name = "Test"
    handler.current_zip_limit = 1000

    sync_files = cluster_common.SyncFiles(b"cmd", logging.getLogger("wazuh"), handler)

    # Test first condition
    await sync_files.sync(files_to_sync, files_metadata, 1, task_pool=None)
    send_request_mock.assert_has_calls([call(command=b'cmd', data=b''), call(command=b'cmd_r', data=ANY)])

    # Test FileNotFoundError raised when deleting compressed_data file
    with patch('os.unlink', side_effect=FileNotFoundError):
        compressed_data = "files/path/"
        with patch("wazuh.core.cluster.cluster.compress_files", return_value=(compressed_data, {})):
            send_request_mock.side_effect = None
            logger = logging.getLogger('wazuh')
            with patch.object(logger, "error") as logger_mock:
                await sync_files.sync(files_to_sync, files_metadata, 1, task_pool=None)
                logger_mock.assert_called_with(f"File {compressed_data} could not be removed/not found. "
                                               f"May be due to a lost connection.")
