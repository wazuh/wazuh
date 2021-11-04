# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging
import os
import pytest
import sys
import threading
import time
import uvloop
from contextvars import ContextVar
from datetime import datetime
from freezegun import freeze_time
from unittest.mock import patch, mock_open, MagicMock, call
from wazuh.core import exception

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.core.cluster import common as cluster_common, client, worker, master, server
        from wazuh.core.cluster.dapi import dapi
        from wazuh.core import common

# Global variables

cluster_items = {'node': 'master-node',
                 'intervals': {'worker': {'connection_retry': 1, "sync_integrity": 2, "sync_agent_info": 5},
                               "communication": {"timeout_receiving_file": 1, "timeout_dapi_request": 1}},
                 "files": {"cluster_item_key": {"remove_subdirs_if_empty": True, "permissions": "value"}}}
fernet_key = "0" * 32
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
loop = asyncio.new_event_loop()


def get_master_handler():
    """Auxiliary function."""
    with patch('asyncio.get_running_loop', return_value=loop):
        abstract_client = client.AbstractClientManager(configuration={'node_name': 'master', 'nodes': ['master'],
                                                                      'port': 1111},
                                                       cluster_items={'node': 'master-node',
                                                                      'intervals': {'worker': {'connection_retry': 1}}},
                                                       enable_ssl=False, performance_test=False, logger=None,
                                                       concurrency_test=False, file='None', string=20)

    return master.MasterHandler(server=abstract_client, loop=loop, fernet_key=fernet_key, cluster_items=cluster_items)


# Test ReceiveIntegrityTask class

@patch("asyncio.create_task")
@patch("wazuh.core.cluster.master.ReceiveIntegrityTask.set_up_coro")
def test_rit_init(set_up_coro_mock, create_task_mock):
    """Test if the ReceiveIntegrityTask is properly initialized."""

    receive_integrity_task = master.ReceiveIntegrityTask(wazuh_common=cluster_common.WazuhCommon(),
                                                         logger=logging.getLogger("wazuh"))

    assert isinstance(receive_integrity_task.wazuh_common, cluster_common.WazuhCommon)
    assert isinstance(receive_integrity_task.logger, logging.Logger)
    set_up_coro_mock.assert_called_once()
    create_task_mock.assert_called_once()


@patch("asyncio.create_task")
def test_rit_set_up_coro(create_task_mock):
    """Check if the function is called when the worker sends its integrity information."""

    class WazuhCommonMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        def sync_integrity(self, task, info):
            """Auxiliary method."""
            pass

    wazuh_common_mock = WazuhCommonMock()
    receive_integrity_task = master.ReceiveIntegrityTask(wazuh_common=wazuh_common_mock,
                                                         logger=logging.getLogger("wazuh"))
    assert receive_integrity_task.set_up_coro() == wazuh_common_mock.sync_integrity
    create_task_mock.assert_called_once()


@patch("asyncio.create_task")
@patch("wazuh.core.cluster.common.ReceiveFileTask.done_callback")
def test_rit_done_callback(super_callback_mock, create_task_mock):
    """Check if the synchronization process was correct."""

    class WazuhCommonMock:
        """Auxiliary class."""

        def __init__(self):
            self.extra_valid_requested = False
            self.sync_integrity_free = None

        def sync_integrity(self, task, info):
            """Auxiliary method."""
            pass

    wazuh_common_mock = WazuhCommonMock()
    receive_integrity_task = master.ReceiveIntegrityTask(wazuh_common=wazuh_common_mock,
                                                         logger=logging.getLogger("wazuh"))
    receive_integrity_task.done_callback()

    create_task_mock.assert_called_once()
    super_callback_mock.assert_called_once_with(None)
    assert wazuh_common_mock.sync_integrity_free is True


# Test ReceiveExtraValidTask class

@patch("asyncio.create_task")
@patch("wazuh.core.cluster.master.ReceiveExtraValidTask.set_up_coro")
def test_revt_init(set_up_coro_mock, create_task_mock):
    """Test the correct initialization of the ReceiveExtraValidTask class."""

    receive_extra_valid_task = master.ReceiveExtraValidTask(wazuh_common=cluster_common.WazuhCommon(),
                                                            logger=logging.getLogger("wazuh"))

    assert isinstance(receive_extra_valid_task.wazuh_common, cluster_common.WazuhCommon)
    assert isinstance(receive_extra_valid_task.logger, logging.Logger)
    set_up_coro_mock.assert_called_once()
    create_task_mock.assert_called_once()


@patch("asyncio.create_task")
def test_revt_set_up_coro(create_task_mock):
    """Check if the function is called when the worker sends its integrity information."""

    class WazuhCommonMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        def sync_extra_valid(self, task, info):
            """Auxiliary method."""
            pass

    wazuh_common_mock = WazuhCommonMock()
    receive_extra_valid_task = master.ReceiveExtraValidTask(wazuh_common=wazuh_common_mock,
                                                            logger=logging.getLogger("wazuh"))
    assert receive_extra_valid_task.set_up_coro() == wazuh_common_mock.sync_extra_valid
    create_task_mock.assert_called_once()


@patch("asyncio.create_task")
@patch("wazuh.core.cluster.common.ReceiveFileTask.done_callback")
@patch("wazuh.core.cluster.master.ReceiveExtraValidTask.set_up_coro")
def test_revt_done_callback(set_up_coro_mock, super_callback_mock, create_task_mock):
    """Check if the synchronization process was correct."""

    class WazuhCommonMock:
        """Auxiliary class."""

        def __init__(self):
            self.extra_valid_requested = None
            self.sync_integrity_free = None

        def sync_integrity(self, task, info):
            """Auxiliary method."""
            pass

    wazuh_common_mock = WazuhCommonMock()
    receive_extra_valid_task = master.ReceiveExtraValidTask(wazuh_common=wazuh_common_mock,
                                                            logger=logging.getLogger("wazuh"))
    receive_extra_valid_task.done_callback()

    create_task_mock.assert_called_once()
    super_callback_mock.assert_called_once_with(None)
    set_up_coro_mock.assert_called_once()
    assert wazuh_common_mock.sync_integrity_free is True
    assert wazuh_common_mock.extra_valid_requested is False


# Test ReceiveAgentInfoTask class

@patch("asyncio.create_task")
@patch("wazuh.core.cluster.master.ReceiveAgentInfoTask.set_up_coro")
def test_rait_init(set_up_coro_mock, create_task_mock):
    """Test the correct initialization of the ReceiveAgentInfoTask object."""

    receive_agent_info_task = master.ReceiveAgentInfoTask(wazuh_common=cluster_common.WazuhCommon(),
                                                          logger=logging.getLogger("wazuh"), task_id="0101")

    assert isinstance(receive_agent_info_task.wazuh_common, cluster_common.WazuhCommon)
    assert isinstance(receive_agent_info_task.logger, logging.Logger)
    assert receive_agent_info_task.task_id == "0101"
    set_up_coro_mock.assert_called_once()
    create_task_mock.assert_called_once()


@patch("asyncio.create_task")
def test_rait_set_up_coro(create_task_mock):
    """Check if the function is called when the worker sends its integrity information."""

    class WazuhCommonMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        def sync_wazuh_db_info(self, task_id):
            """Auxiliary method."""
            pass

    wazuh_common_mock = WazuhCommonMock()
    receive_agent_info_task = master.ReceiveAgentInfoTask(wazuh_common=wazuh_common_mock,
                                                          logger=logging.getLogger("wazuh"), task_id="0101")
    assert receive_agent_info_task.set_up_coro() == wazuh_common_mock.sync_wazuh_db_info
    create_task_mock.assert_called_once()


@patch("asyncio.create_task")
@patch("wazuh.core.cluster.common.ReceiveStringTask.done_callback")
@patch("wazuh.core.cluster.master.ReceiveAgentInfoTask.set_up_coro")
def test_rait_done_callback(set_up_coro_mock, super_callback_mock, create_task_mock):
    """Check if the synchronization process was correct."""

    class WazuhCommonMock:
        """Auxiliary class."""

        def __init__(self):
            self.sync_agent_info_free = None

        def sync_integrity(self, task, info):
            """Auxiliary method."""
            pass

    wazuh_common_mock = WazuhCommonMock()
    receive_agent_info_task = master.ReceiveAgentInfoTask(wazuh_common=wazuh_common_mock,
                                                          logger=logging.getLogger("wazuh"), task_id="0101")
    receive_agent_info_task.done_callback()

    create_task_mock.assert_called_once()
    super_callback_mock.assert_called_once_with(None)
    set_up_coro_mock.assert_called_once()
    assert wazuh_common_mock.sync_agent_info_free is True


# Test MasterHandler class

def test_master_handler_init():
    """Test the proper initialization of the MasterHandler class."""

    with patch('wazuh.core.cluster.master.context_tag', ContextVar('', default="")) as cv:
        master_handler = get_master_handler()

        assert master_handler.sync_agent_info_free is True
        assert master_handler.sync_integrity_free is True
        assert master_handler.extra_valid_requested is False
        assert master_handler.integrity_check_status == {'date_start_master': datetime.fromtimestamp(0),
                                                         'date_end_master': datetime.fromtimestamp(0)}
        assert master_handler.integrity_sync_status == {'date_start_master': datetime.fromtimestamp(0),
                                                        'tmp_date_start_master': datetime.fromtimestamp(0),
                                                        'date_end_master': datetime.fromtimestamp(0),
                                                        'total_extra_valid': 0,
                                                        'total_files': {'missing': 0, 'shared': 0, 'extra': 0,
                                                                        'extra_valid': 0}}
        assert master_handler.sync_agent_info_status == {'date_start_master': datetime.fromtimestamp(0),
                                                         'date_end_master': datetime.fromtimestamp(0),
                                                         'n_synced_chunks': 0}
        assert master_handler.version == ""
        assert master_handler.cluster_name == ""
        assert master_handler.node_type == ""
        assert master_handler.task_loggers == {}
        assert master_handler.tag == "Worker"
        assert cv.get() == master_handler.tag


def test_master_handler_to_dict():
    """Check if the worker healthcheck information is properly obtained."""

    master_handler = get_master_handler()
    output = master_handler.to_dict()

    assert "info" in output
    assert "name" in output["info"]
    assert output["info"]["name"] == master_handler.name
    assert "type" in output["info"]
    assert output["info"]["type"] == master_handler.node_type
    assert "version" in output["info"]
    assert output["info"]["version"] == master_handler.version
    assert "ip" in output["info"]
    assert output["info"]["ip"] == master_handler.ip

    assert "status" in output
    assert "sync_integrity_free" in output["status"]
    assert output["status"]["sync_integrity_free"] == master_handler.sync_integrity_free
    assert "last_check_integrity" in output["status"]
    assert output["status"]["last_check_integrity"] == {'date_start_master': datetime(1970, 1, 1, 1, 0),
                                                        'date_end_master': datetime(1970, 1, 1, 1, 0)}
    assert "last_sync_integrity" in output["status"]
    assert output["status"]["last_sync_integrity"] == {'date_start_master': datetime(1970, 1, 1, 1, 0),
                                                       'date_end_master': datetime(1970, 1, 1, 1, 0),
                                                       'total_extra_valid': 0,
                                                       'total_files': {'missing': 0, 'shared': 0, 'extra': 0,
                                                                       'extra_valid': 0}}
    assert "last_sync_agentinfo" in output["status"]
    assert output["status"]["last_sync_agentinfo"] == master_handler.sync_agent_info_status
    assert "last_keep_alive" in output["status"]
    assert output["status"]["last_keep_alive"] == master_handler.last_keepalive


@patch.object(logging.getLogger("wazuh"), "debug")
def test_master_handler_process_request(logger_mock):
    """Test if all the available commands that can be received from the worker are properly defined."""

    master_handler = get_master_handler()

    class DapiMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        def add_request(self, data):
            """Auxiliary method."""
            pass

        def send_request(self, command, error_msg):
            """Auxiliary method."""
            pass

    class Server:
        """Auxiliary class."""

        def __init__(self):
            self.local_server = LocalServer()
            self.sendsync = DapiMock()

    class LocalServer:
        """Auxiliary class."""

        def __init__(self):
            self.clients = {b"dapi_client".decode(): DapiMock()}

    # Test first condition
    with patch("wazuh.core.cluster.master.MasterHandler.get_permission", return_value=b"ok") as get_permission_mock:
        assert master_handler.process_request(command=b'syn_i_w_m_p', data=b"data") == b"ok"
        assert master_handler.process_request(command=b'syn_a_w_m_p', data=b"data") == b"ok"
        get_permission_mock.assert_has_calls([call(b'syn_i_w_m_p'), call(b'syn_a_w_m_p')])

    # Test the second condition
    with patch("wazuh.core.cluster.master.MasterHandler.setup_sync_integrity",
               return_value=b"ok") as setup_sync_integrity_mock:
        assert master_handler.process_request(command=b'syn_i_w_m', data=b"data") == b"ok"
        assert master_handler.process_request(command=b'syn_e_w_m', data=b"data") == b"ok"
        assert master_handler.process_request(command=b'syn_a_w_m', data=b"data") == b"ok"
        setup_sync_integrity_mock.assert_has_calls(
            [call(b'syn_i_w_m', b"data"), call(b'syn_e_w_m', b"data"), call(b'syn_a_w_m', b"data")])

    # Test the third condition
    with patch("wazuh.core.cluster.master.MasterHandler.end_receiving_integrity_checksums",
               return_value=b"ok") as end_receiving_integrity_checksums_mock:
        assert master_handler.process_request(command=b'syn_i_w_m_e', data=b"data") == b"ok"
        assert master_handler.process_request(command=b'syn_e_w_m_e', data=b"data") == b"ok"
        end_receiving_integrity_checksums_mock.assert_has_calls([call("data"), call("data")])

    # Test the fourth condition
    with patch("wazuh.core.cluster.master.MasterHandler.process_sync_error_from_worker",
               return_value=b"ok") as process_sync_error_from_worker_mock:
        assert master_handler.process_request(command=b'syn_i_w_m_r', data=b"data") == b"ok"
        process_sync_error_from_worker_mock.assert_called_once_with(b"data")

    # Test the fifth condition
    master_handler.server.dapi = DapiMock()

    with patch.object(DapiMock, "add_request") as add_request_mock:
        master_handler.name = "Master"
        assert master_handler.process_request(command=b'dapi',
                                              data=b"data") == (b"ok", b"Added request to API requests queue")
        add_request_mock.assert_called_once_with(master_handler.name.encode() + b"*" + b"data")

    # Test the sixth condition
    with patch("wazuh.core.cluster.master.MasterHandler.process_dapi_res", return_value=b"ok") as process_dapi_res_mock:
        assert master_handler.process_request(command=b'dapi_res', data=b"data") == b"ok"
        process_dapi_res_mock.assert_called_once_with(b"data")

    # Test the seventh condition
    master_handler.server = Server()
    with patch("asyncio.create_task") as create_task_mock:
        assert master_handler.process_request(command=b'dapi_err',
                                              data=b"dapi_client error_msg") == (b'ok',
                                                                                 b'DAPI error forwarded to worker')
        create_task_mock.assert_called_once_with(DapiMock().send_request(b"dapi_err", b"error_msg"))

    # Test the eighth condition
    with patch("wazuh.core.cluster.master.MasterHandler.get_nodes", return_value=(["cmd", "res"])) as get_nodes_mock:
        with patch("json.loads", return_value=b"ok") as json_loads_mock:
            with patch("json.dumps", return_value="ok") as json_dumps_mock:
                assert master_handler.process_request(command=b'get_nodes', data=b"data") == ("cmd", b"ok")
                json_loads_mock.assert_called_once_with(b"data")
                get_nodes_mock.assert_called_once_with(b"ok")
                json_dumps_mock.assert_called_once_with("res")

    # Test the ninth condition
    with patch("wazuh.core.cluster.master.MasterHandler.get_health", return_value=(["cmd", "res"])) as get_health_mock:
        with patch("json.loads", return_value=b"ok") as json_loads_mock:
            with patch("json.dumps", return_value="ok") as json_dumps_mock:
                assert master_handler.process_request(command=b'get_health', data=b"data") == ("cmd", b"ok")
                json_loads_mock.assert_called_once_with(b"data")
                get_health_mock.assert_called_once_with(b"ok")
                json_dumps_mock.assert_called_once()

    # Test the tenth condition
    with patch.object(DapiMock, "add_request") as add_request_mock:
        assert master_handler.process_request(command=b'sendsync', data=b"data") == (b'ok',
                                                                                     b'Added request to SendSync '
                                                                                     b'requests queue')
        add_request_mock.assert_called_once_with(master_handler.name.encode() + b"*" + b"data")

    # Test the eleventh condition
    with patch("wazuh.core.cluster.server.AbstractServerHandler.process_request",
               return_value=b"ok") as process_request_mock:
        assert master_handler.process_request(command=b'random', data=b"data") == b"ok"
        process_request_mock.assert_called_once_with(b"random", b"data")

    logger_mock.assert_has_calls([call("Command received: b'syn_i_w_m_p'"), call("Command received: b'syn_a_w_m_p'"),
                                  call("Command received: b'syn_i_w_m'"), call("Command received: b'syn_e_w_m'"),
                                  call("Command received: b'syn_a_w_m'"), call("Command received: b'syn_i_w_m_e'"),
                                  call("Command received: b'syn_e_w_m_e'"), call("Command received: b'syn_i_w_m_r'"),
                                  call("Command received: b'dapi'"), call("Command received: b'dapi_res'"),
                                  call("Command received: b'dapi_err'"), call("Command received: b'get_nodes'"),
                                  call("Command received: b'get_health'"), call("Command received: b'sendsync'"),
                                  call("Command received: b'random'")])


@pytest.mark.asyncio
@patch("asyncio.wait_for")
@patch("wazuh.core.cluster.master.uuid4", return_value=10101010)
async def test_master_handler_execute_ok(uuid4_mock, wait_for_mock):
    """Check if a DAPI response is properly sent."""

    master_handler = get_master_handler()

    class Server:
        """Auxiliary class."""

        def __init__(self):
            self.pending_api_requests = {uuid4_mock.return_value: None}
            self.clients = {"client": LocalServer()}

    class LocalServer:
        """Auxiliary class."""

        def __init__(self):
            pass

        @staticmethod
        async def send_request(command, data):
            """Auxiliary method."""
            return b"ok"

    master_handler.server = Server()

    # Test the first and second if
    with patch.object(LocalServer, "send_request", return_value=b"ok") as send_request_mock:
        assert await master_handler.execute(command=b'dapi_fwd', data=b"client request", wait_for_complete=True) == ""
        send_request_mock.assert_called_once_with(b"dapi", str(uuid4_mock.return_value).encode() + b' ' + b"request")

    # Test the first elif and first try with a timeout
    with patch("wazuh.core.cluster.master.MasterHandler.send_request", return_value=b"result") as send_request_mock:
        assert await master_handler.execute(command=b'dapi', data=b"client request", wait_for_complete=False) == ""
        send_request_mock.assert_called_once_with(b"dapi",
                                                  str(uuid4_mock.return_value).encode() + b' ' + b"client request")

    # Test the first and second else
    with patch("wazuh.core.cluster.master.MasterHandler.process_request",
               return_value=[b"ok", b""]) as process_request_mock:
        assert await master_handler.execute(command=b'random', data=b"client request", wait_for_complete=True) == ""
        process_request_mock.assert_called_once_with(command=b"random", data=b"client request")

    uuid4_mock.assert_called_with()
    assert uuid4_mock.call_count == 3
    assert wait_for_mock.call_count == 2


@pytest.mark.asyncio
@patch("wazuh.core.cluster.master.uuid4", return_value=10101010)
async def test_master_handler_execute_ko(uuid4_mock):
    """Check if exceptions are being properly raised."""

    master_handler = get_master_handler()

    class Server:
        """Auxiliary class."""

        def __init__(self):
            self.pending_api_requests = {uuid4_mock.return_value: None}
            self.clients = {b"client": ""}

    master_handler.server = Server()

    # Test the first exception
    with pytest.raises(exception.WazuhClusterError, match=r'.* 3022 .*'):
        await master_handler.execute(command=b'dapi_fwd', data=b"client request", wait_for_complete=True)

    # Test the second exception
    with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
        with patch("wazuh.core.cluster.master.MasterHandler.send_request", return_value=b"result"):
            with pytest.raises(exception.WazuhClusterError, match=r".* 3021 .*"):
                await master_handler.execute(command=b'dapi', data=b"client request", wait_for_complete=True)

    # Test the third exception
    with patch("wazuh.core.cluster.master.MasterHandler.process_request",
               return_value=[b"error", b""]) as process_request_mock:
        with pytest.raises(exception.WazuhClusterError, match=r".* 3022 .*"):
            await master_handler.execute(command=b'random', data=b"client request", wait_for_complete=True)


@patch("os.path.exists", return_value=False)
@patch("os.path.join", return_value="/some/path")
@patch("wazuh.core.cluster.master.utils.mkdir_with_mode")
@patch("wazuh.core.cluster.master.metadata.__version__", "version")
@patch("wazuh.core.cluster.server.AbstractServerHandler.hello", return_value=(b"ok", "payload"))
def test_master_handler_hello_ok(super_hello_mock, mkdir_with_mode_mock, join_mock, path_exists_mock):
    """Check if the 'hello' command received from worker is being correctly processed."""

    master_handler = get_master_handler()

    class Server:
        """Auxiliary class."""

        def __init__(self):
            self.configuration = {}

    master_handler.server = Server()
    master_handler.server.configuration["name"] = "cluster_name"

    assert master_handler.hello(b"name cluster_name node_type version") == (b"ok", "payload")

    super_hello_mock.assert_called_once_with(b"name")
    mkdir_with_mode_mock.assert_called_once_with("/some/path")
    join_mock.assert_called_once_with(common.wazuh_path, "queue", "cluster", None)
    path_exists_mock.assert_called_once_with("/some/path")

    assert "Integrity check" in master_handler.task_loggers
    assert "Integrity sync" in master_handler.task_loggers
    assert "Agent-info sync" in master_handler.task_loggers

    assert isinstance(master_handler.task_loggers["Integrity check"], logging.Logger)
    assert isinstance(master_handler.task_loggers["Integrity sync"], logging.Logger)
    assert isinstance(master_handler.task_loggers["Agent-info sync"], logging.Logger)

    assert master_handler.version == "version"
    assert master_handler.cluster_name == "cluster_name"
    assert master_handler.node_type == "node_type"


@patch("wazuh.core.cluster.master.metadata.__version__", "random")
@patch("wazuh.core.cluster.server.AbstractServerHandler.hello", return_value=(b"ok", "payload"))
def test_master_handler_hello_ko(super_hello_mock):
    """Check if the exceptions are being properly raised."""

    master_handler = get_master_handler()

    class Server:
        """Auxiliary class."""

        def __init__(self):
            self.configuration = {}

    master_handler.server = Server()
    master_handler.server.configuration["name"] = "other name"

    #  Test the first exception
    with pytest.raises(exception.WazuhClusterError, match=r".* 3030 .*"):
        master_handler.hello(b"name cluster_name node_type version")

    #  Test the second exception
    master_handler.server.configuration["name"] = "cluster_name"
    with pytest.raises(exception.WazuhClusterError, match=r".* 3031 .*"):
        master_handler.hello(b"name cluster_name node_type version")

    super_hello_mock.assert_called_with(b"name")
    assert super_hello_mock.call_count == 2


def test_master_handler_get_manager():
    """Check if the Master object is properly returned."""

    assert isinstance(get_master_handler().get_manager(), client.AbstractClientManager)


def test_master_handler_process_dapi_res_ok():
    """Check if a DAPI response is properly processed."""

    class Server:
        """Auxiliary class."""

        def __init__(self):
            self.pending_api_requests = {"req_id": {"Response": None, "Event": event_mock}}
            self.payload = b"payload"
            self.local_server = LocalServer()

    class LocalServer:
        """Auxiliary class."""

        def __init__(self):
            self.clients = {"req_id": None}

    class EventMock:
        """Auxiliary class."""

        def __init__(self):
            self.set_flag = False

        def set(self):
            """Auxiliary method."""
            self.set_flag = True

    # Test the first condition
    master_handler = get_master_handler()
    event_mock = EventMock()

    master_handler.server = Server()
    master_handler.in_str[b"string_id"] = Server()

    assert master_handler.process_dapi_res(b"req_id string_id") == (b'ok', b'Forwarded response')
    assert master_handler.in_str == {}
    assert event_mock.set_flag is True
    assert master_handler.server.pending_api_requests["req_id"]["Response"] == "payload"

    # Test the second condition
    master_handler.server.pending_api_requests = {}
    with patch("asyncio.create_task") as create_task_mock:
        assert master_handler.process_dapi_res(b"req_id string_id") == (b'ok', b'Response forwarded to worker')
        create_task_mock.assert_called_once()


def test_master_handler_process_dapi_res_ko():
    """Check if exceptions are being properly raised."""

    master_handler = get_master_handler()

    class Server:
        """Auxiliary class."""

        def __init__(self):
            self.pending_api_requests = {}
            self.local_server = LocalServer()

    class LocalServer:
        """Auxiliary class."""

        def __init__(self):
            self.clients = {}

    master_handler.server = Server()

    with pytest.raises(exception.WazuhClusterError, match=r".* 3032 .*"):
        master_handler.process_dapi_res(b"req_id string_id")


def test_master_handler_get_nodes():
    """Check if the 'get_nodes' request is being properly processed."""

    class Server:
        """Auxiliary class."""

        def __init__(self):
            self.get_connected_nodes_flag = False

        def get_connected_nodes(self, arguments: dict = None):
            """Auxiliary method."""

            self.get_connected_nodes_flag = True
            return {"ok": "ok_value"}

    master_handler = get_master_handler()
    master_handler.server = Server()

    assert master_handler.get_nodes({"arguments": None}) == (b"ok", {"ok": "ok_value"})
    assert master_handler.server.get_connected_nodes_flag is True


def test_master_handler_get_health():
    """Check if the 'get_health' request is being properly processed."""

    class Server:
        """Auxiliary class."""

        def __init__(self):
            self.get_health_flag = False

        def get_health(self, arguments: dict = None):
            """Auxiliary method."""

            self.get_health_flag = True
            return {"ok": "ok_value"}

    master_handler = get_master_handler()
    master_handler.server = Server()

    assert master_handler.get_health(filter_nodes=None) == (b"ok", {"ok": "ok_value"})
    assert master_handler.server.get_health_flag is True


def test_master_handler_get_permission():
    """Check the right response to whether a sync process is in progress or not."""

    master_handler = get_master_handler()

    # Test the first condition
    assert master_handler.get_permission(b'syn_i_w_m_p') == (b"ok", str(master_handler.sync_integrity_free).encode())

    # Test the second condition
    assert master_handler.get_permission(b'syn_a_w_m_p') == (b"ok", str(master_handler.sync_agent_info_free).encode())

    # Test the third condition
    assert master_handler.get_permission(b'random') == (b"ok", str(False).encode())


@patch("wazuh.core.cluster.common.WazuhCommon.setup_receive_file", return_value=b"ok")
def test_master_handler_setup_sync_integrity(setup_receive_file_mock):
    """Check if the synchronization process was correctly started."""

    master_handler = get_master_handler()

    # Test the first condition
    assert master_handler.setup_sync_integrity(b'syn_i_w_m', b"data") == b"ok"
    assert master_handler.sync_integrity_free is False

    # Test the second condition
    assert master_handler.setup_sync_integrity(b'syn_e_w_m', b"data") == b"ok"

    # Test the third condition
    assert master_handler.setup_sync_integrity(b'syn_a_w_m', b"data") == b"ok"
    assert master_handler.sync_agent_info_free is False

    # Test the fourth condition
    assert master_handler.setup_sync_integrity(b'random', b"data") == b"ok"

    setup_receive_file_mock.assert_has_calls(
        [call(master.ReceiveIntegrityTask, b"data"), call(master.ReceiveExtraValidTask, b"data"),
         call(master.ReceiveAgentInfoTask, b"data"), call(None, b"data")])


@patch("wazuh.core.cluster.common.WazuhCommon.error_receiving_file", return_value=b"ok")
def test_master_handler_process_sync_error_from_worker(error_receiving_file_mock):
    """Check if an error is properly managed when it takes place."""

    master_handler = get_master_handler()
    assert master_handler.process_sync_error_from_worker(b"error") == b"ok"
    assert master_handler.sync_integrity_free is True
    error_receiving_file_mock.assert_called_once_with(b"error".decode())


@patch("wazuh.core.cluster.common.WazuhCommon.end_receiving_file", return_value=b"ok")
def test_master_handler_end_receiving_integrity_checksums(end_receiving_file_mock):
    """Check if the function is started after receiving a file."""

    assert get_master_handler().end_receiving_integrity_checksums("task_and_file_names") == b"ok"
    end_receiving_file_mock.assert_called_once_with("task_and_file_names")


@pytest.mark.asyncio
@freeze_time("2021-11-02")
@patch("json.dumps", return_value="")
@patch("wazuh.core.wdb.socket.socket")
@patch("wazuh.core.cluster.master.time", return_value=0)
@patch("wazuh.core.wdb.WazuhDBConnection.send", return_value=["ok"])
@patch("json.loads", return_value={"chunks": "1", "set_data_command": "1"})
@patch("wazuh.core.cluster.master.MasterHandler.send_request", return_value="response")
async def test_master_handler_sync_wazuh_db_info_ok(send_request_mock, loads_mock, send_mock, time_mock, socket_mock,
                                                    json_dumps_mock):
    """Check if the chunks of data are updated and iterated."""

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._info = []
            self._error = []
            self._debug = []
            self._debug2 = []

        def info(self, data):
            """Auxiliary method."""
            self._info.append(data)

        def debug(self, data):
            """Auxiliary method."""
            self._debug.append(data)

        def debug2(self, data):
            """Auxiliary method."""
            self._debug2.append(data)

        def error(self, data):
            """Auxiliary method."""
            self._error.append(data)

    class TaskMock:
        """Auxiliary class."""

        def __init__(self):
            self.payload = b"payload"

    master_handler = get_master_handler()
    master_handler.task_loggers["Agent-info sync"] = LoggerMock()
    master_handler.in_str[b"task_id"] = TaskMock()

    # Test the first and second try, also nested else
    assert await master_handler.sync_wazuh_db_info(b"task_id") == send_request_mock.return_value

    # Test the first try and second try, nested if
    send_mock.return_value = ["not_ok"]
    assert await master_handler.sync_wazuh_db_info(b"task_id") == send_request_mock.return_value

    # Test the first try and second except
    send_mock.side_effect = Exception()
    assert await master_handler.sync_wazuh_db_info(b"task_id") == send_request_mock.return_value

    send_request_mock.assert_has_calls([call(command=b'syn_m_a_e', data=b''), call(command=b'syn_m_a_e', data=b''),
                                        call(command=b'syn_m_a_e', data=b'')])
    loads_mock.assert_has_calls([call("payload"), call("payload"), call("payload")])
    assert socket_mock.call_count == 3
    json_dumps_mock.assert_has_calls(
        [call({'updated_chunks': 1, 'error_messages': []}), call({'updated_chunks': 0, 'error_messages': [['not_ok']]}),
         call({'updated_chunks': 0, 'error_messages': ['']})])
    send_mock.assert_has_calls([call("1 1", raw=True), call("1 1", raw=True), call("1 1", raw=True)])
    assert time_mock.call_count == 6
    assert master_handler.task_loggers["Agent-info sync"]._info == ["Starting",
                                                                    "Finished in 0.000s (1 chunks updated).",
                                                                    "Starting",
                                                                    "Finished in 0.000s (0 chunks updated).",
                                                                    "Starting",
                                                                    "Finished in 0.000s (0 chunks updated)."]
    assert master_handler.task_loggers["Agent-info sync"]._error == ["Response for chunk 0/1 was not 'ok': ['not_ok']"]
    assert master_handler.task_loggers["Agent-info sync"]._debug == ["All chunks updated in wazuh-db in 0.000000s.",
                                                                     "All chunks updated in wazuh-db in 0.000000s.",
                                                                     "All chunks updated in wazuh-db in 0.000000s.", ]
    assert master_handler.task_loggers["Agent-info sync"]._debug2 == ["Sending chunk 1/1 to wazuh-db: 1",
                                                                      "Sending chunk 1/1 to wazuh-db: 1",
                                                                      "Sending chunk 1/1 to wazuh-db: 1"]


@pytest.mark.asyncio
@patch("wazuh.core.wdb.socket.socket")
@patch("json.loads", return_value={"chunks": "1", "set_data_command": "1"})
@patch("wazuh.core.cluster.master.MasterHandler.send_request", return_value="response")
async def test_master_handler_sync_wazuh_db_info_ko(send_request_mock, loads_mock, socket_mock):
    """Check if the exceptions are correctly handled."""

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._info = []

        def info(self, data):
            """Auxiliary method."""
            self._info.append(data)

    class TaskMock:
        """Auxiliary class."""

        def __init__(self):
            self.payload = b"payload"

    master_handler = get_master_handler()
    master_handler.task_loggers["Agent-info sync"] = LoggerMock()
    master_handler.in_str[b"task_id"] = TaskMock()

    # Test the first except
    with pytest.raises(exception.WazuhClusterError, match=r'.* 3035 .*'):
        await master_handler.sync_wazuh_db_info(b"not_task_id")

    # Test the second exception
    loads_mock.side_effect = ValueError()
    with pytest.raises(exception.WazuhClusterError, match=r'.* 3036 .*'):
        await master_handler.sync_wazuh_db_info(b"task_id")

    send_request_mock.assert_has_calls(
        [call(command=b"syn_m_a_err", data=b"error while trying to access string under task_id b'not_task_id'."),
         call(command=b"syn_m_a_err", data=b"error while trying to load JSON: ")])
    loads_mock.assert_has_calls([call("payload")])
    assert socket_mock.call_count == 2
    assert master_handler.task_loggers["Agent-info sync"]._info == ["Starting", "Starting"]


@pytest.mark.asyncio
@patch("shutil.rmtree")
@patch("asyncio.wait_for")
@patch("wazuh.core.cluster.master.MasterHandler.process_files_from_worker")
@patch("wazuh.core.cluster.cluster.decompress_files", return_value=("files_metadata", "/decompressed/files/path"))
async def test_master_handler_sync_worker_files_ok(wait_for_mock, process_files_from_worker_mock,
                                                   decompress_files_mock, rmtree_mock):
    """Check if the extra_valid files are properly received and processed."""

    class EventMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        async def wait(self):
            """Auxiliary method."""
            pass

    class TaskMock:
        """Auxiliary class."""

        def __init__(self):
            self.filename = "filename"

    master_handler = get_master_handler()
    master_handler.sync_tasks["task_id"] = TaskMock()

    await master_handler.sync_worker_files("task_id", EventMock(), logging.getLogger("wazuh"))
    wait_for_mock.assert_called_once_with("filename")
    process_files_from_worker_mock.assert_called_once_with("files_metadata", "/decompressed/files/path",
                                                           logging.getLogger("wazuh"))
    decompress_files_mock.assert_called_once()
    rmtree_mock.assert_called_once_with("/decompressed/files/path")


@pytest.mark.asyncio
async def test_master_handler_sync_worker_files_ko():
    """Check if the exceptions are properly raised."""

    class EventMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        async def wait(self):
            """Auxiliary method."""
            pass

    class TaskMock:
        """Auxiliary class."""

        def __init__(self):
            self.filename = Exception()

    master_handler = get_master_handler()
    master_handler.sync_tasks["task_id"] = TaskMock()

    with pytest.raises(Exception):
        await master_handler.sync_worker_files("task_id", EventMock(), logging.getLogger("wazuh"))


@pytest.mark.asyncio
@freeze_time("2021-11-02")
@patch.object(logging.getLogger("wazuh"), "info")
@patch("wazuh.core.cluster.master.MasterHandler.sync_worker_files")
async def test_master_handler_sync_extra_valid(sync_worker_files_mock, logger_mock):
    """Check if the extra_valid sync process is properly run."""

    master_handler = get_master_handler()
    master_handler.task_loggers["Integrity sync"] = logging.getLogger("wazuh")
    await master_handler.sync_extra_valid("task_id", None)

    sync_worker_files_mock.assert_called_once_with("task_id", None, logging.getLogger("wazuh"))
    assert master_handler.integrity_sync_status['date_end_master'] == "2021-11-02T00:00:00.000000Z"
    logger_mock.assert_called_once_with(
        "Finished in {:.3f}s.".format(
            (datetime.strptime(master_handler.integrity_sync_status['date_end_master'], '%Y-%m-%dT%H:%M:%S.%fZ') -
             master_handler.integrity_sync_status['tmp_date_start_master']).total_seconds()))
    assert master_handler.integrity_sync_status['date_start_master'] == "1970-01-01T00:00:00.000000Z"
    assert master_handler.extra_valid_requested is False
    assert master_handler.sync_integrity_free is True


@pytest.mark.asyncio
@patch("shutil.rmtree")
@freeze_time("2021-11-02")
@patch("asyncio.wait_for")
@patch("functools.reduce", return_value=False)
@patch.object(logging.getLogger("wazuh"), "info")
@patch.object(logging.getLogger("wazuh"), "debug")
@patch("wazuh.core.cluster.master.MasterHandler.send_request", return_value=b"ok")
@patch("wazuh.core.cluster.cluster.compare_files", return_value=({"extra_valid": "False"}, 0))
@patch("wazuh.core.cluster.cluster.decompress_files", return_value=("files_metadata", "/decompressed/files/path"))
async def test_master_handler_sync_integrity_ok(decompress_files_mock, compare_files_mock, send_request_mock,
                                                debug_mock,
                                                info_mock, reduce_mock, wait_for_mock, rmtree_mock):
    """Test if the comparison between the local and received files is properly done."""

    master_handler = get_master_handler()
    side_effect_function_value = 0

    class EventMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        async def wait(self):
            """Auxiliary method."""
            pass

    class TaskMock:
        """Auxiliary class."""

        def __init__(self):
            self.filename = "filename"

    class ServerMock:
        """Auxiliary class."""

        def __init__(self):
            self.integrity_control = True

    def side_effect_function(command, data):
        """Auxiliary method to return a particular output when needed."""
        if command == b'syn_m_c':
            return b"ok"
        elif command == b'syn_m_c_e' and side_effect_function_value == 0:
            return Exception()
        elif command == b'syn_m_c_e' and side_effect_function_value == 1:
            return b"Error"

    master_handler.sync_tasks = {"task_id": TaskMock()}
    master_handler.task_loggers["Integrity check"] = logging.getLogger("wazuh")
    master_handler.server = ServerMock()

    # Test the first condition (if)
    assert await master_handler.sync_integrity("task_id", EventMock()) == b"ok"

    decompress_files_mock.assert_called_once_with(TaskMock().filename)
    compare_files_mock.assert_called_once_with(True, decompress_files_mock.return_value[0], None)
    send_request_mock.assert_called_once_with(command=b"syn_m_c_ok", data=b"")
    debug_mock.assert_has_calls(
        [call("Waiting to receive zip file from worker."), call("Received file from worker: 'filename'")])
    info_mock.assert_has_calls(
        [call("Starting. Received metadata of 14 files."), call("Finished in 0.000s. Sync not required.")])
    reduce_mock.assert_called_once()
    wait_for_mock.assert_called_once()
    rmtree_mock.assert_called_once_with(decompress_files_mock.return_value[1])

    # Reset all the used mocks
    all_mocks = [decompress_files_mock, compare_files_mock, send_request_mock, debug_mock, info_mock, reduce_mock,
                 wait_for_mock, rmtree_mock]
    for mock in all_mocks:
        mock.reset_mock()

    with patch("os.unlink") as unlink_mock:
        with patch("wazuh.core.cluster.cluster.compress_files", return_value="compressed_data") as compress_files_mock:
            with patch("wazuh.core.cluster.master.MasterHandler.send_file") as send_file_mock:
                # Test the second condition (else -> try -> finally -> if)
                reduce_mock.return_value = True
                master_handler.task_loggers["Integrity sync"] = logging.getLogger("wazuh")
                compare_files_mock.return_value = ({"missing": {"key": "value"}, "shared": {"key": "value"},
                                                    "extra": "1", "extra_valid": ""}, 0)

                assert await master_handler.sync_integrity("task_id", EventMock()) == b"ok"
                decompress_files_mock.assert_called_once_with(TaskMock().filename)
                compare_files_mock.assert_called_once_with(True, decompress_files_mock.return_value[0], None)
                send_request_mock.assert_has_calls(
                    [call(command=b"syn_m_c", data=b""), call(command=b"syn_m_c_e", data=b"ok compressed_data")])
                info_mock.assert_has_calls(
                    [call("Starting. Received metadata of 14 files."), call("Finished in 0.000s. Sync required."),
                     call("Starting."), call(
                        "Files to create in worker: 1 | Files to update in worker: 1 | Files to delete in worker: 1 | "
                        "Files to receive: 0"), call("Finished in 0.000s.")])
                debug_mock.assert_has_calls(
                    [call("Waiting to receive zip file from worker."), call("Received file from worker: 'filename'"),
                     call("Compressing files to be synced in worker."),
                     call("Zip with files to be synced sent to worker."), call("Finished sending files to worker.")])
                reduce_mock.assert_called_once()
                wait_for_mock.assert_called_once()
                rmtree_mock.assert_called_once_with(decompress_files_mock.return_value[1])
                unlink_mock.assert_called_once_with(compress_files_mock.return_value)
                compress_files_mock.assert_called_once_with(None, {'key'}, compare_files_mock.return_value[0])
                send_file_mock.assert_called_once_with(compress_files_mock.return_value)
                assert master_handler.integrity_sync_status['date_end_master'] == "2021-11-02T00:00:00.000000Z"
                assert master_handler.integrity_sync_status['date_start_master'] == "2021-11-02T00:00:00.000000Z"

                # Reset all the mocks
                all_mocks += [unlink_mock, compress_files_mock, send_file_mock]
                for mock in all_mocks:
                    mock.reset_mock()

                with patch.object(logging.getLogger("wazuh"), "error") as error_mock:
                    with patch("json.dumps", return_value="error") as json_dumps_mock:
                        # Test the first if present in try (else -> try -> if -> if)
                        # and second exception (else -> 2º except)
                        compare_files_mock.return_value = ({"missing": {"key": "value"}, "shared": {"key": "value"},
                                                            "extra": "1", "extra_valid": "1"}, 0)
                        send_request_mock.return_value = Exception()
                        assert await master_handler.sync_integrity("task_id",
                                                                   EventMock()) == send_request_mock.return_value

                        decompress_files_mock.assert_called_once_with(TaskMock().filename)
                        compare_files_mock.assert_called_once_with(True, decompress_files_mock.return_value[0], None)
                        send_request_mock.assert_has_calls(
                            [call(command=b'syn_m_c', data=b''),
                             call(command=b'syn_m_c_r', data=b'None error')])
                        info_mock.assert_has_calls(
                            [call("Starting. Received metadata of 14 files."),
                             call("Finished in 0.000s. Sync required."),
                             call("Starting."), call(
                                "Files to create in worker: 1 | Files to update in worker: 1 "
                                "| Files to delete in worker: 1 | Files to receive: 1")])
                        debug_mock.assert_has_calls(
                            [call("Waiting to receive zip file from worker."),
                             call("Received file from worker: 'filename'"),
                             call("Compressing files to be synced in worker."),
                             call("Zip with files to be synced sent to worker."),
                             call("Finished sending files to worker.")])
                        reduce_mock.assert_called_once()
                        wait_for_mock.assert_called_once()
                        rmtree_mock.assert_called_once_with(decompress_files_mock.return_value[1])
                        unlink_mock.assert_called_once_with(compress_files_mock.return_value)
                        compress_files_mock.assert_called_once_with(None, {'key'}, compare_files_mock.return_value[0])
                        error_mock.assert_called_once_with("Error sending files information: ")
                        json_dumps_mock.assert_called_once_with(
                            exception.WazuhClusterError(code=1000, extra_message=str(send_request_mock.return_value)),
                            cls=cluster_common.WazuhJSONEncoder)
                        send_file_mock.assert_not_called()

                        # Reset all the mocks
                        all_mocks += [error_mock, json_dumps_mock]
                        for mock in all_mocks:
                            mock.reset_mock()

                        # Test the first if present in try (else -> try -> if -> else)
                        # and first exception (else -> 1º except)
                        compare_files_mock.return_value = ({"missing": {"key": "value"}, "shared": {"key": "value"},
                                                            "extra": "1", "extra_valid": "1"}, 0)
                        send_request_mock.return_value = b"Error"
                        assert await master_handler.sync_integrity("task_id",
                                                                   EventMock()) == send_request_mock.return_value

                        decompress_files_mock.assert_called_once_with(TaskMock().filename)
                        compare_files_mock.assert_called_once_with(True, decompress_files_mock.return_value[0], None)
                        send_request_mock.assert_has_calls(
                            [call(command=b'syn_m_c', data=b''),
                             call(command=b'syn_m_c_r', data=b'None error')])
                        info_mock.assert_has_calls(
                            [call("Starting. Received metadata of 14 files."),
                             call("Finished in 0.000s. Sync required."),
                             call("Starting."), call(
                                "Files to create in worker: 1 | Files to update in worker: 1 "
                                "| Files to delete in worker: 1 | Files to receive: 1")])
                        debug_mock.assert_has_calls(
                            [call("Waiting to receive zip file from worker."),
                             call("Received file from worker: 'filename'"),
                             call("Compressing files to be synced in worker."),
                             call("Zip with files to be synced sent to worker."),
                             call("Finished sending files to worker.")])
                        reduce_mock.assert_called_once()
                        wait_for_mock.assert_called_once()
                        rmtree_mock.assert_called_once_with(decompress_files_mock.return_value[1])
                        unlink_mock.assert_called_once_with(compress_files_mock.return_value)
                        compress_files_mock.assert_called_once_with(None, {'key'}, compare_files_mock.return_value[0])
                        error_mock.assert_called_once_with(
                            "Error sending files information: Error 3016 - Received an error response: b'Error'")
                        json_dumps_mock.assert_called_once_with(exception.WazuhClusterError(3016, "b'Error'"),
                                                                cls=cluster_common.WazuhJSONEncoder)
                        send_file_mock.assert_not_called()

                        # Reset all the mocks
                        for mock in all_mocks:
                            mock.reset_mock()

                        # Test the second if inside try (else -> try -> 2º if)
                        send_request_mock.side_effect = side_effect_function
                        await master_handler.sync_integrity("task_id", EventMock())

                        decompress_files_mock.assert_called_once_with(TaskMock().filename)
                        compare_files_mock.assert_called_once_with(True, decompress_files_mock.return_value[0], None)
                        send_request_mock.assert_has_calls(
                            [call(command=b'syn_m_c', data=b''),
                             call(command=b'syn_m_c_e', data=b'ok compressed_data'),
                             call(command=b'syn_m_c_r', data=b'ok error')])
                        info_mock.assert_has_calls(
                            [call("Starting. Received metadata of 14 files."),
                             call("Finished in 0.000s. Sync required."),
                             call("Starting."), call(
                                "Files to create in worker: 1 | Files to update in worker: 1 "
                                "| Files to delete in worker: 1 | Files to receive: 1")])
                        debug_mock.assert_has_calls(
                            [call("Waiting to receive zip file from worker."),
                             call("Received file from worker: 'filename'"),
                             call("Compressing files to be synced in worker."),
                             call("Zip with files to be synced sent to worker."),
                             call("Finished sending files to worker.")])
                        reduce_mock.assert_called_once()
                        wait_for_mock.assert_called_once()
                        rmtree_mock.assert_called_once_with(decompress_files_mock.return_value[1])
                        unlink_mock.assert_called_once_with(compress_files_mock.return_value)
                        compress_files_mock.assert_called_once_with(None, {'key'}, compare_files_mock.return_value[0])
                        error_mock.assert_called_once_with("Error sending files information: ")
                        json_dumps_mock.assert_called_once_with(
                            exception.WazuhClusterError(code=1000, extra_message=""),
                            cls=cluster_common.WazuhJSONEncoder)
                        send_file_mock.assert_called_once_with("compressed_data")

                        # Reset all mocks
                        for mock in all_mocks:
                            mock.reset_mock()

                        # Test the second if inside try (else -> try -> 2º elif)
                        side_effect_function_value = 1
                        await master_handler.sync_integrity("task_id", EventMock())

                        decompress_files_mock.assert_called_once_with(TaskMock().filename)
                        compare_files_mock.assert_called_once_with(True, decompress_files_mock.return_value[0], None)
                        send_request_mock.assert_has_calls(
                            [call(command=b'syn_m_c', data=b''),
                             call(command=b'syn_m_c_e', data=b'ok compressed_data'),
                             call(command=b'syn_m_c_r', data=b'ok error')])
                        info_mock.assert_has_calls(
                            [call("Starting. Received metadata of 14 files."),
                             call("Finished in 0.000s. Sync required."),
                             call("Starting."), call(
                                "Files to create in worker: 1 | Files to update in worker: 1 "
                                "| Files to delete in worker: 1 | Files to receive: 1")])
                        debug_mock.assert_has_calls(
                            [call("Waiting to receive zip file from worker."),
                             call("Received file from worker: 'filename'"),
                             call("Compressing files to be synced in worker."),
                             call("Zip with files to be synced sent to worker."),
                             call("Finished sending files to worker.")])
                        reduce_mock.assert_called_once()
                        wait_for_mock.assert_called_once()
                        rmtree_mock.assert_called_once_with(decompress_files_mock.return_value[1])
                        unlink_mock.assert_called_once_with(compress_files_mock.return_value)
                        compress_files_mock.assert_called_once_with(None, {'key'}, compare_files_mock.return_value[0])
                        error_mock.assert_called_once_with(
                            "Error sending files information: Error 3016 - Received an error response: Error")
                        json_dumps_mock.assert_called_once_with(
                            exception.WazuhClusterError(code=3016, extra_message="Error"),
                            cls=cluster_common.WazuhJSONEncoder)
                        send_file_mock.assert_called_once_with("compressed_data")


@pytest.mark.asyncio
@freeze_time("2021-11-02")
@patch("asyncio.wait_for")
async def test_master_handler_sync_integrity_ko(wait_for_mock):
    """Check if the exceptions are properly raised."""

    class EventMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        async def wait(self):
            """Auxiliary method."""
            pass

    class TaskMock:
        """Auxiliary class."""

        def __init__(self):
            self.filename = Exception()

    master_handler = get_master_handler()
    master_handler.sync_tasks = {"task_id": TaskMock()}
    master_handler.task_loggers["Integrity check"] = logging.getLogger("wazuh")

    with pytest.raises(Exception):
        await master_handler.sync_integrity("task_id", EventMock())

    wait_for_mock.assert_called_once()


@pytest.mark.asyncio
@patch("os.path.join", return_value="/some/path")
@patch("builtins.set", return_value={1, 3, 4, 5})
@patch("os.path.basename", return_value="client.keys")
@patch("wazuh.core.cluster.master.Agent.get_agents_overview", return_value={"items": ("1", "2", "3")})
async def test_master_handler_process_files_from_worker_ok(get_agents_overview_mock, basename_mock, set_mock,
                                                           path_join_mock):
    """Check if the local files are updated and the received iterated over."""

    master_handler = get_master_handler()
    files_metadata = {
        "data": {"merged": "1", "merge_type": "type", "merge_name": "name", "cluster_item_key": "queue/agent-groups/"}}

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._debug2 = []
            self._warning = []
            self._error = []

        def debug2(self, data):
            """Auxiliary method."""
            self._debug2.append(data)

        def warning(self, data):
            """Auxiliary method."""
            self._warning.append(data)

        def error(self, data):
            """Auxiliary method."""
            self._error.append(data)

    class StatMock:
        """Auxiliary class."""

        def __init__(self):
            self.st_mtime = "20"

    def reset_mock(data):
        """Auxiliary method."""
        for mock in data:
            mock.reset_mock()

    all_mocks = [get_agents_overview_mock, basename_mock, set_mock, path_join_mock]

    # Test the first and second try
    # Nested function: try -> 1º if and 1º exception
    master_handler.logger = LoggerMock()
    await master_handler.process_files_from_worker(files_metadata, "/decompressed/files/path",
                                                   master_handler.logger)

    get_agents_overview_mock.assert_called_once_with(select=['name'], limit=None)
    basename_mock.assert_called_once_with('data')
    assert set_mock.call_count == 6
    path_join_mock.assert_called_once_with(common.wazuh_path, "data")
    assert master_handler.logger._debug2 == [f"Warning updating file 'data': {exception.WazuhClusterError(3007)}",
                                             f"Received {1} group assignments for non-existent agents. Skipping."]
    assert master_handler.logger._warning == ["Client.keys received in a master node"]

    # Reset all the used mocks
    reset_mock(all_mocks)

    basename_mock.return_value = "/os/path/basename"
    with patch("wazuh.core.cluster.cluster.unmerge_info",
               return_value=[("/file/path", "file data", "file time")]) as unmerge_info_mock:
        # Test the first try and second try -> nested function: try -> 2º if -> for -> try -> if -> else
        # Also, outside the nested function, the second if is being tested
        master_handler.logger = LoggerMock()
        await master_handler.process_files_from_worker(files_metadata, "/decompressed/files/path",
                                                       master_handler.logger)
        get_agents_overview_mock.assert_called_once_with(select=['name'], limit=None)
        basename_mock.assert_has_calls([call('data'), call('/file/path'), call('/file/path')])
        assert set_mock.call_count == 3
        path_join_mock.assert_has_calls([call(common.wazuh_path, 'data'),
                                         call(common.wazuh_path, '/file/path'),
                                         call(common.wazuh_path, 'queue', 'cluster', None,
                                              '/os/path/basename')])
        unmerge_info_mock.assert_called_once_with('type', '/decompressed/files/path', 'name')
        assert master_handler.logger._debug2 == ["Received group of an non-existent agent '/os/path/basename'",
                                                 'Received 1 group assignments for non-existent agents. Skipping.']
        assert master_handler.logger._warning == []

        # Reset all the used mocks
        all_mocks.append(unmerge_info_mock)
        reset_mock(all_mocks)

        # Test the first try and second try -> nested function: try ->  2º if -> for -> try -> if -> if
        files_metadata["data"]["cluster_item_key"] = None
        master_handler.logger = LoggerMock()
        await master_handler.process_files_from_worker(files_metadata, "/decompressed/files/path",
                                                       master_handler.logger)
        get_agents_overview_mock.assert_called_once_with(select=['name'], limit=None)
        basename_mock.assert_has_calls([call('data'), call('/file/path'), call('/file/path')])
        set_mock.assert_called_once()
        path_join_mock.assert_has_calls([call(common.wazuh_path, 'data'),
                                         call(common.wazuh_path, '/file/path'),
                                         call(common.wazuh_path, 'queue', 'cluster', None,
                                              '/os/path/basename')])
        unmerge_info_mock.assert_called_once_with('type', '/decompressed/files/path', 'name')
        assert master_handler.logger._debug2 == ["Received group of an non-existent agent '/os/path/basename'"]
        assert master_handler.logger._warning == []

        # Reset all the used mocks
        reset_mock(all_mocks)

        # Test the second exception present in the nested function
        unmerge_info_mock.side_effect = Exception()
        master_handler.logger = LoggerMock()
        await master_handler.process_files_from_worker(files_metadata,
                                                       "/decompressed/files/path",
                                                       master_handler.logger)

        get_agents_overview_mock.assert_called_once_with(select=['name'], limit=None)
        basename_mock.assert_any_call('data')
        set_mock.assert_called_once()
        path_join_mock.assert_called_once_with(common.wazuh_path, "data")
        unmerge_info_mock.assert_called_once_with('type', '/decompressed/files/path', 'name')
        assert master_handler.logger._debug2 == ["Error updating file 'data': "]
        assert master_handler.logger._warning == []
        assert master_handler.logger._error == ["Errors updating worker files: None: 1"]

        unmerge_info_mock.side_effect = None

        # Reset all the used mocks
        reset_mock(all_mocks)

        with patch("os.path.isfile", return_value=True) as isfile_mock:
            with patch("os.stat", return_value=StatMock()) as stat_mock:
                basename_mock.return_value = 1
                files_metadata["data"]["cluster_item_key"] = "cluster_item_key"
                all_mocks += [isfile_mock, stat_mock]

                # Test inside the nested function: try -> 2º if -> for -> try -> try -> .. -> if -> if
                unmerge_info_mock.return_value = [("/file/path", "file data", "1970-01-01 00:00:00.000")]
                master_handler.logger = LoggerMock()
                await master_handler.process_files_from_worker(files_metadata,
                                                               "/decompressed/files/path",
                                                               master_handler.logger)

                get_agents_overview_mock.assert_called_once_with(select=['name'], limit=None)
                basename_mock.assert_has_calls([call('data'), call('/file/path'), call('/file/path')])
                assert set_mock.call_count == 5
                path_join_mock.assert_has_calls([call(common.wazuh_path, 'data'),
                                                 call(common.wazuh_path, '/file/path'),
                                                 call(common.wazuh_path, 'queue', 'cluster', None, 1)])
                unmerge_info_mock.assert_called_once_with('type', '/decompressed/files/path', 'name')
                assert master_handler.logger._debug2 == ["Receiving an old file (/file/path)"]
                assert master_handler.logger._warning == []
                isfile_mock.assert_called_once_with("/some/path")
                stat_mock.assert_called_once_with("/some/path")

                # Reset all the used mocks
                reset_mock(all_mocks)

                with patch("builtins.open") as open_mock:
                    all_mocks.append(open_mock)
                    unmerge_info_mock.return_value = [("/file/path", "file data", "2021-11-02 00:00:00")]
                    # Test the nested function try -> 2º if -> for -> except -> if
                    open_mock.side_effect = Exception()
                    files_metadata["data"]["cluster_item_key"] = None
                    master_handler.logger = LoggerMock()
                    await master_handler.process_files_from_worker(files_metadata,
                                                                   "/decompressed/files/path",
                                                                   master_handler.logger)

                    get_agents_overview_mock.assert_called_once_with(select=['name'], limit=None)
                    basename_mock.assert_has_calls([call('data'), call('/file/path'), call('/file/path')])
                    assert set_mock.call_count == 3
                    path_join_mock.assert_has_calls([call(common.wazuh_path, 'data'),
                                                     call(common.wazuh_path, '/file/path'),
                                                     call(common.wazuh_path, 'queue', 'cluster', None, 1)])
                    unmerge_info_mock.assert_called_once_with('type', '/decompressed/files/path', 'name')
                    assert master_handler.logger._debug2 == []
                    assert master_handler.logger._warning == []
                    isfile_mock.assert_called_once_with("/some/path")
                    stat_mock.assert_called_once_with("/some/path")
                    open_mock.assert_called_once_with('/some/path', 'wb')

                    # Reset all the used mocks
                    reset_mock(all_mocks)

                    # Test the nested function try -> 2º if -> for -> except -> else
                    files_metadata["data"]["cluster_item_key"] = "cluster_item_key"
                    master_handler.logger = LoggerMock()

                    await master_handler.process_files_from_worker(files_metadata,
                                                                   "/decompressed/files/path",
                                                                   master_handler.logger)

                    get_agents_overview_mock.assert_called_once_with(select=['name'], limit=None)
                    basename_mock.assert_has_calls([call('data'), call('/file/path'), call('/file/path')])
                    assert set_mock.call_count == 1
                    path_join_mock.assert_has_calls([call(common.wazuh_path, 'data'),
                                                     call(common.wazuh_path, '/file/path'),
                                                     call(common.wazuh_path, 'queue', 'cluster', None, 1)])
                    unmerge_info_mock.assert_called_once_with('type', '/decompressed/files/path', 'name')
                    assert master_handler.logger._debug2 == []
                    assert master_handler.logger._warning == []
                    isfile_mock.assert_called_once_with("/some/path")
                    stat_mock.assert_called_once_with("/some/path")
                    open_mock.assert_called_once_with('/some/path', 'wb')

                    # Reset all the used mocks
                    reset_mock(all_mocks)

                    with patch("wazuh.core.cluster.master.utils.safe_move") as safe_move_mock:
                        with patch("wazuh.core.common.wazuh_uid", return_value="wazuh_uid") as wazuh_uid_mock:
                            with patch("wazuh.core.common.wazuh_gid", return_value="wazuh_gid") as wazuh_gid_mock:
                                all_mocks += [safe_move_mock, wazuh_uid_mock, wazuh_gid_mock]
                                open_mock.side_effect = None

                                # Test inside the nested function: try -> 2º if -> for -> try -> try
                                master_handler.logger = LoggerMock()
                                await master_handler.process_files_from_worker(files_metadata,
                                                                               "/decompressed/files/path",
                                                                               master_handler.logger)

                                get_agents_overview_mock.assert_called_once_with(select=['name'], limit=None)
                                basename_mock.assert_has_calls([call('data'), call('/file/path'), call('/file/path')])
                                assert set_mock.call_count == 21
                                path_join_mock.assert_has_calls([call(common.wazuh_path, 'data'),
                                                                 call(common.wazuh_path, '/file/path'),
                                                                 call(common.wazuh_path, 'queue', 'cluster', None, 1)])
                                unmerge_info_mock.assert_called_once_with('type', '/decompressed/files/path', 'name')
                                assert master_handler.logger._debug2 == []
                                assert master_handler.logger._warning == []
                                isfile_mock.assert_called_once_with("/some/path")
                                stat_mock.assert_called_once_with("/some/path")
                                open_mock.assert_called_once_with('/some/path', 'wb')
                                safe_move_mock.assert_called_once()
                                wazuh_uid_mock.assert_called_once_with()
                                wazuh_gid_mock.assert_called_once_with()

                                # Reset all the used mocks
                                reset_mock(all_mocks)

        with patch("wazuh.core.cluster.master.utils.safe_move") as safe_move_mock:
            with patch("wazuh.core.common.wazuh_uid", return_value="wazuh_uid") as wazuh_uid_mock:
                with patch("wazuh.core.common.wazuh_gid", return_value="wazuh_gid") as wazuh_gid_mock:
                    # Test the nested function try -> else and also first except in the main function
                    get_agents_overview_mock.side_effect = Exception()
                    files_metadata["data"]["merged"] = ""
                    master_handler.logger = LoggerMock()
                    await master_handler.process_files_from_worker(files_metadata,
                                                                   "/decompressed/files/path",
                                                                   master_handler.logger)

                    get_agents_overview_mock.assert_called_once_with(select=['name'], limit=None)
                    basename_mock.assert_any_call('data')
                    assert set_mock.call_count == 8
                    path_join_mock.assert_has_calls([call(common.wazuh_path, 'data'),
                                                     call('/decompressed/files/path', 'data')])
                    unmerge_info_mock.assert_not_called()
                    assert master_handler.logger._debug2 == ["Error getting agent ids: "]
                    assert master_handler.logger._warning == []
                    assert master_handler.logger._error == []
                    safe_move_mock.assert_called_once_with('/some/path', '/some/path',
                                                           ownership=('wazuh_uid', 'wazuh_gid'),
                                                           permissions='value')
                    wazuh_uid_mock.assert_called_once_with()
                    wazuh_gid_mock.assert_called_once_with()


@pytest.mark.asyncio
@patch("os.path.join", side_effect=Exception())
@patch("builtins.set", return_value={1, 3, 4, 5})
@patch("wazuh.core.cluster.master.Agent.get_agents_overview", return_value={"items": ("1", "2", "3")})
async def test_master_handler_process_files_from_worker_ko(get_agents_overview_mock, set_mock, join_mock):
    """Check if all the exceptions are being properly raised."""
    master_handler = get_master_handler()
    files_metadata = {
        "data": {"merged": "1", "merge_type": "type", "merge_name": "name", "cluster_item_key": "queue/agent-groups/"}}

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._debug2 = []
            self._error = []

        def debug2(self, data):
            """Auxiliary method."""
            self._debug2.append(data)

        def error(self, data):
            """Auxiliary method."""
            self._error.append(data)

    master_handler.logger = LoggerMock()
    with pytest.raises(Exception):
        await master_handler.process_files_from_worker(files_metadata, "/decompressed/files/path",
                                                       master_handler.logger)

    get_agents_overview_mock.assert_called_once_with(select=['name'], limit=None)
    join_mock.assert_called_once_with(common.wazuh_path, "data")
    assert set_mock.call_count == 5


def test_master_handler_get_logger():
    """Check if the right Logger object is being returned."""

    master_handler = get_master_handler()

    # Test the first if
    assert master_handler.get_logger() == master_handler.logger
    assert "random_tag" not in master_handler.task_loggers

    master_handler.task_loggers["random_tag"] = "output"
    assert master_handler.get_logger("random_tag") == "output"


@patch.object(logging.getLogger("wazuh"), "info")
@patch("wazuh.core.cluster.master.server.AbstractServerHandler.connection_lost")
def test_master_handler_connection_lost(connection_lost_mock, logger_mock):
    """Check if all the pending tasks are closed when the connection between workers and master is lost."""

    master_handler = get_master_handler()
    master_handler.logger = logging.getLogger("wazuh")

    class PendingTaskMock:
        """Auxiliary class."""

        def __init__(self):
            self.task = TaskMock()

    class TaskMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        def cancel(self):
            """Auxiliary method."""
            pass

    master_handler.sync_tasks = {"key": PendingTaskMock()}
    master_handler.connection_lost(Exception())


# Test Master class

@patch('asyncio.get_running_loop', return_value=loop)
def test_master_init(get_running_loop_mock):
    """Check if the Master class is being properly initialized."""

    master_class = master.Master(performance_test=False, concurrency_test=False,
                                 configuration={'node_name': 'master', 'nodes': ['master'], 'port': 1111},
                                 cluster_items={'node': 'master-node',
                                                'intervals': {'worker': {'connection_retry': 1}}},
                                 enable_ssl=False)

    assert master_class.integrity_control == {}
    assert master_class.tasks == [master_class.check_clients_keepalive, master_class.file_status_update,
                                  master_class.dapi.run, master_class.sendsync.run]
    assert master_class.handler_class == master.MasterHandler
    assert isinstance(master_class.dapi, dapi.APIRequestQueue)
    assert isinstance(master_class.sendsync, dapi.SendSyncRequestQueue)
    assert master_class.pending_api_requests == {}


@patch('asyncio.get_running_loop', return_value=loop)
@patch("wazuh.core.cluster.master.metadata.__version__", "1.0.0")
def test_master_to_dict(get_running_loop_mock):
    """Check if the master's healthcheck information is properly obtained."""

    master_class = master.Master(performance_test=False, concurrency_test=False,
                                 configuration={'node_name': 'master', 'nodes': ['master'], 'port': 1111,
                                                "node_type": "master"},
                                 cluster_items={'node': 'master-node',
                                                'intervals': {'worker': {'connection_retry': 1}}},
                                 enable_ssl=False)

    assert master_class.to_dict() == {
        'info': {'name': master_class.configuration['node_name'], 'type': master_class.configuration['node_type'],
                 'version': "1.0.0", 'ip': master_class.configuration['nodes'][0]}}


@pytest.mark.asyncio
@freeze_time("2021-11-02")
@patch('asyncio.get_running_loop', return_value=loop)
@patch("wazuh.core.cluster.cluster.get_files_status", return_value="ok")
async def test_master_file_status_update_ok(get_running_loop_mock, get_file_status_mock):
    """Check if the file status is properly obtained."""

    master_class = master.Master(performance_test=False, concurrency_test=False,
                                 configuration={'node_name': 'master', 'nodes': ['master'], 'port': 1111,
                                                "node_type": "master"},
                                 cluster_items={'node': 'master-node',
                                                'intervals': {'worker': {'connection_retry': 1},
                                                              'master': {'recalculate_integrity': 1}}},
                                 enable_ssl=False)

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._info = []

        def info(self, data):
            """Auxiliary method."""
            self._info.append(data)

    async def final_function():
        """Auxiliary method."""

        await master_class.file_status_update()

    def middle_function():
        """Auxiliary method."""

        _loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_loop)

        _loop.run_until_complete(final_function())
        _loop.close()

    logger_mock = LoggerMock()

    with patch("wazuh.core.cluster.master.Master.setup_task_logger",
               return_value=logger_mock) as setup_task_logger_mock:
        _thread = threading.Thread(target=middle_function)
        _thread.daemon = True
        _thread.start()
        time.sleep(2)

        assert "Starting." in logger_mock._info
        assert "Finished in 0.000s. Calculated metadata of 2 files." in logger_mock._info
        get_file_status_mock.assert_called_once_with()
        setup_task_logger_mock.assert_called_once_with('Local integrity')
        assert master_class.integrity_control == "ok"


@pytest.mark.asyncio
@freeze_time("2021-11-02")
@patch.object(logging.getLogger("wazuh"), "info")
@patch.object(logging.getLogger("wazuh"), "error")
@patch('asyncio.get_running_loop', return_value=loop)
@patch("wazuh.core.cluster.cluster.get_files_status", side_effect=Exception())
@patch("wazuh.core.cluster.master.Master.setup_task_logger", return_value=logging.getLogger("wazuh"))
async def test_master_file_status_update_ko(set_up_task_logger_mock, get_running_loop_mock,
                                            get_file_status_mock, error_mock, info_mock):
    """Check if the exception is working properly."""

    master_class = master.Master(performance_test=False, concurrency_test=False,
                                 configuration={'node_name': 'master', 'nodes': ['master'], 'port': 1111,
                                                "node_type": "master"},
                                 cluster_items={'node': 'master-node',
                                                'intervals': {'worker': {'connection_retry': 1},
                                                              'master': {'recalculate_integrity': 1}}},
                                 enable_ssl=False)

    async def final_function():
        """Auxiliary method."""

        await master_class.file_status_update()

    def middle_function():
        """Auxiliary method."""

        _loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_loop)

        _loop.run_until_complete(final_function())
        _loop.close()

    _thread = threading.Thread(target=middle_function)
    _thread.daemon = True
    _thread.start()
    time.sleep(2)

    set_up_task_logger_mock.assert_called_once_with("Local integrity")
    info_mock.assert_has_calls([call('Starting.'), call('Finished in 0.000s. Calculated metadata of 0 files.')])
    error_mock.assert_called_once_with('Error calculating local file integrity: ')
    get_file_status_mock.assert_called_once_with()


@patch('asyncio.get_running_loop', return_value=loop)
@patch("wazuh.core.agent.Agent.get_agents_overview", return_value={"totalItems": "value"})
def test_master_get_health(get_running_loop_mock, get_agent_overview_mock):
    """Check if nodes and the synchronization information is properly obtained."""

    master_class = master.Master(performance_test=False, concurrency_test=False,
                                 configuration={'node_name': 'master', 'nodes': ['master'], 'port': 1111,
                                                "node_type": "master"},
                                 cluster_items={'node': 'master-node',
                                                'intervals': {'master': {'recalculate_integrity': 1}}},
                                 enable_ssl=False)

    # Test when filter_node is {}
    assert master_class.get_health({}) == {'n_connected_nodes': 0, 'nodes': {}}

    # Test when filter_node is None
    assert master_class.get_health(None) == {'n_connected_nodes': 0, 'nodes': {'master': {
        'info': {'name': 'master', 'type': 'master', 'version': '4.3.0', 'ip': 'master', 'n_active_agents': 'value'}}}}

    with patch("wazuh.core.cluster.master.Master.to_dict", return_value={
        'info': {'name': "worker", 'type': "worker", 'version': "1.0.0", 'ip': master_class.configuration['nodes'][0]},
         'status': {"last_keep_alive": 10}}) as to_dict_mock:
        # Test when filter_node is not None or empty
        master_class.configuration["node_name"] = "worker"
        master_class.configuration["node_type"] = "worker"
        assert master_class.get_health({"worker": "value"}) == {'n_connected_nodes': 0, 'nodes': {'worker': {
            'info': {'name': 'worker', 'type': 'worker', 'version': '1.0.0', 'ip': 'master',
                     'n_active_agents': 'value'}, 'status': {'last_keep_alive': '1970-01-01T01:00:10.000000Z'}}}}
        to_dict_mock.assert_called_once_with()


@patch('asyncio.get_running_loop', return_value=loop)
def test_master_get_node(get_running_loop_mock):
    """Check if basic information about the node is being returned."""

    master_class = master.Master(performance_test=False, concurrency_test=False,
                                 configuration={'node_name': 'master', 'nodes': ['master'], 'port': 1111,
                                                "node_type": "master", "name": "master"},
                                 cluster_items={'node': 'master-node',
                                                'intervals': {'worker': {'connection_retry': 1}}},
                                 enable_ssl=False)

    assert master_class.get_node() == {'type': master_class.configuration['node_type'],
                                       'cluster': master_class.configuration['name'],
                                       'node': master_class.configuration['node_name']}
