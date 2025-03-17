# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging
import sys
from collections import defaultdict
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Dict
from unittest.mock import patch, MagicMock, AsyncMock, call, ANY

import pytest
import uvloop
from freezegun import freeze_time

from wazuh.core import exception

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.core.cluster import common as cluster_common, client, master
        from wazuh.core.cluster.master import DEFAULT_DATE
        from wazuh.core import common
        from wazuh.core.cluster.dapi import dapi
        from wazuh.core.common import DECIMALS_DATE_FORMAT

# Global variables

cluster_items = {'node': 'master-node',
                 'intervals': {'worker': {'connection_retry': 1, "sync_integrity": 2, "sync_agent_info": 5},
                               "communication": {"timeout_receiving_file": 1, "timeout_dapi_request": 1,
                                                 "max_zip_size": 1073741824, "min_zip_size": 31457280,
                                                 "zip_limit_tolerance": 0.2},
                               'master': {'max_locked_integrity_time': 0, 'timeout_agent_info': 0,
                                          'timeout_extra_valid': 0, 'authentication_pool_size': 2,
                                          'process_pool_size': 10,
                                          'recalculate_integrity': 0, 'sync_agent_groups': 1,
                                          'agent_group_start_delay': 1}},
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


def get_master():
    """Auxiliary function."""
    with patch('asyncio.get_running_loop', return_value=loop):
        return master.Master(performance_test=False, concurrency_test=False,
                             configuration={'node_name': 'master', 'nodes': ['master'],
                                            'port': 1111, 'node_type': 'master'},
                             cluster_items=cluster_items, enable_ssl=False)


# Test ReceiveIntegrityTask class

@pytest.mark.asyncio
async def test_rit_init():
    """Test if the ReceiveIntegrityTask is properly initialized."""
    master_common = get_master_handler()
    with patch.object(master_common, 'integrity_check') as integrity_check_mock:
        receive_integrity_task = master.ReceiveIntegrityTask(wazuh_common=master_common,
                                                            logger=logging.getLogger("wazuh"))
        assert isinstance(receive_integrity_task.wazuh_common, cluster_common.WazuhCommon)
        assert isinstance(receive_integrity_task.logger, logging.Logger)
        integrity_check_mock.assert_called_once()


@patch("asyncio.create_task")
def test_rit_set_up_coro(create_task_mock):
    """Check if the function is called when the worker sends its integrity information."""

    class WazuhCommonMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        def integrity_check(self, task, info):
            """Auxiliary method."""
            pass

    wazuh_common_mock = WazuhCommonMock()
    receive_integrity_task = master.ReceiveIntegrityTask(wazuh_common=wazuh_common_mock,
                                                         logger=logging.getLogger("wazuh"))
    assert receive_integrity_task.set_up_coro() == wazuh_common_mock.integrity_check
    create_task_mock.assert_called_once()


@patch("asyncio.create_task")
@patch("wazuh.core.cluster.common.ReceiveFileTask.done_callback")
def test_rit_done_callback(super_callback_mock, create_task_mock):
    """Check if the synchronization process was correct."""

    class WazuhCommonMock:
        """Auxiliary class."""

        def __init__(self):
            self.extra_valid_requested = False
            self.sync_integrity_free = [False]

        def integrity_check(self, task, info):
            """Auxiliary method."""
            pass

    wazuh_common_mock = WazuhCommonMock()
    receive_integrity_task = master.ReceiveIntegrityTask(wazuh_common=wazuh_common_mock,
                                                         logger=logging.getLogger("wazuh"))
    receive_integrity_task.done_callback()

    create_task_mock.assert_called_once()
    super_callback_mock.assert_called_once_with(None)
    assert wazuh_common_mock.sync_integrity_free[0] is True


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
            self.sync_integrity_free = [False]

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
    assert wazuh_common_mock.sync_integrity_free[0] is True
    assert wazuh_common_mock.extra_valid_requested is False


@patch("asyncio.create_task")
@patch("wazuh.core.cluster.master.ReceiveAgentInfoTask.set_up_coro")
def test_rait_init(set_up_coro_mock, create_task_mock):
    """Test the initialization of the ReceiveAgentInfoTask object."""

    receive_agent_info_task = master.ReceiveAgentInfoTask(wazuh_common=cluster_common.WazuhCommon(),
                                                          logger=logging.getLogger("wazuh"), task_id="0101")

    assert isinstance(receive_agent_info_task.wazuh_common, cluster_common.WazuhCommon)
    assert receive_agent_info_task.task_id == "0101"
    set_up_coro_mock.assert_called_once()
    create_task_mock.assert_called_once()


@patch("asyncio.create_task")
@patch("wazuh.core.cluster.master.SendEntireAgentGroupsTask.set_up_coro")
def test_seagt_init(set_up_coro_mock, create_task_mock):
    """Test the initialization of the SendEntireAgentGroupsTask object."""

    receive_agent_groups_task = master.SendEntireAgentGroupsTask(wazuh_common=cluster_common.WazuhCommon(),
                                                                 logger=logging.getLogger("wazuh"))

    assert isinstance(receive_agent_groups_task.wazuh_common, cluster_common.WazuhCommon)
    set_up_coro_mock.assert_called_once()
    create_task_mock.assert_called_once()


@patch("asyncio.create_task")
def test_rait_set_up_coro(create_task_mock):
    """Check if the function is called when the worker sends its agent-info information."""

    class WazuhCommonMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        def sync_wazuh_db_info(self, wazuh_common, task_id):
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
    """Check if the agent-ingo synchronization process was correct."""

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
        assert master_handler.sync_integrity_free[0] is True
        assert isinstance(master_handler.sync_integrity_free[1], datetime)
        assert master_handler.extra_valid_requested is False
        assert master_handler.integrity_check_status == {
            'date_start_master': DEFAULT_DATE,
            'date_end_master': DEFAULT_DATE}
        assert master_handler.integrity_sync_status == {
            'date_start_master': DEFAULT_DATE,
            'tmp_date_start_master': DEFAULT_DATE,
            'date_end_master': DEFAULT_DATE,
            'total_extra_valid': 0,
            'total_files': {'missing': 0, 'shared': 0, 'extra': 0,
                            'extra_valid': 0}}
        assert master_handler.sync_agent_info_status == {
            'date_start_master': DEFAULT_DATE,
            'date_end_master': DEFAULT_DATE,
            'n_synced_chunks': 0}
        assert master_handler.version == ""
        assert master_handler.cluster_name == ""
        assert master_handler.node_type == ""
        assert master_handler.task_loggers == {}
        assert master_handler.tag == "Worker"
        assert master_handler.current_zip_limit == cluster_items['intervals']['communication']['max_zip_size']
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
    assert output["status"]["sync_integrity_free"] == master_handler.sync_integrity_free[0]
    assert "last_check_integrity" in output["status"]
    assert output["status"]["last_check_integrity"] == {
        'date_start_master': DEFAULT_DATE,
        'date_end_master': DEFAULT_DATE}
    assert "last_sync_integrity" in output["status"]
    assert output["status"]["last_sync_integrity"] == {
        'date_start_master': DEFAULT_DATE,
        'date_end_master': DEFAULT_DATE,
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
    with patch("wazuh.core.cluster.common.end_sending_agent_information",
               return_value=b'ok') as end_sending_agent_information_mock:
        master_handler.task_loggers['Agent-groups send'] = logging.getLogger('Agent-groups send')
        master_handler.send_agent_groups_status['date_start'] = '1970-01-01T00:00:00.0Z'

        assert master_handler.process_request(command=b'syn_w_g_e', data=b"data") == b"ok"
        end_sending_agent_information_mock.assert_called_once_with(
            logging.getLogger('Agent-groups send'), 
            datetime.strptime(master_handler.send_agent_groups_status['date_start'], DECIMALS_DATE_FORMAT), "data")

    # Test the sixth condition
    with patch("wazuh.core.cluster.common.end_sending_agent_information",
               return_value=b'ok') as end_sending_agent_information_mock:
        master_handler.task_loggers['Agent-groups send full'] = logging.getLogger('Agent-groups send full')
        master_handler.send_full_agent_groups_status['date_start'] = '1970-01-01T00:00:00.0Z'

        assert master_handler.process_request(command=b'syn_wgc_e', data=b"data") == b"ok"
        end_sending_agent_information_mock.assert_called_once_with(
            logging.getLogger('Agent-groups send full'),
            datetime.strptime(master_handler.send_full_agent_groups_status['date_start'], DECIMALS_DATE_FORMAT), "data")

    # Test the seventh condition
    with patch("wazuh.core.cluster.common.error_receiving_agent_information",
               return_value=b'ok') as error_receiving_agent_information_mock:
        assert master_handler.process_request(command=b'syn_w_g_err', data=b"data") == b"ok"
        error_receiving_agent_information_mock.assert_called_once_with(logging.getLogger('Agent-groups send'),
                                                                       "data", info_type='agent-groups')

    # Test the eighth condition
    with patch("wazuh.core.cluster.common.error_receiving_agent_information",
               return_value=b'ok') as error_receiving_agent_information_mock:
        assert master_handler.process_request(command=b'syn_wgc_err', data=b"data") == b"ok"
        error_receiving_agent_information_mock.assert_called_once_with(logging.getLogger('Agent-groups send full'),
                                                                       "data", info_type='agent-groups')

    # Test the ninth condition
    master_handler.server.dapi = DapiMock()

    with patch.object(DapiMock, "add_request") as add_request_mock:
        master_handler.name = "Master"
        assert master_handler.process_request(command=b'dapi',
                                              data=b"data") == (b"ok", b"Added request to API requests queue")
        add_request_mock.assert_called_once_with(master_handler.name.encode() + b"*" + b"data")

    # Test the tenth condition
    with patch("wazuh.core.cluster.master.MasterHandler.process_dapi_res", return_value=b"ok") as process_dapi_res_mock:
        assert master_handler.process_request(command=b'dapi_res', data=b"data") == b"ok"
        process_dapi_res_mock.assert_called_once_with(b"data")

    # Test the eleventh condition
    with patch("wazuh.core.cluster.master.MasterHandler.get_nodes", return_value=(["cmd", "res"])) as get_nodes_mock:
        with patch("json.loads", return_value=b"ok") as json_loads_mock:
            with patch("json.dumps", return_value="ok") as json_dumps_mock:
                assert master_handler.process_request(command=b'get_nodes', data=b"data") == ("cmd", b"ok")
                json_loads_mock.assert_called_once_with(b"data")
                get_nodes_mock.assert_called_once_with(b"ok")
                json_dumps_mock.assert_called_once_with("res")

    master_handler.server = Server()
    # Test the twelfth condition
    with patch("wazuh.core.cluster.master.MasterHandler.get_health", return_value=(["cmd", "res"])) as get_health_mock:
        with patch("json.loads", return_value=b"ok") as json_loads_mock:
            with patch("json.dumps", return_value="ok") as json_dumps_mock:
                assert master_handler.process_request(command=b'get_health', data=b"data") == ("cmd", b"ok")
                json_loads_mock.assert_called_once_with(b"data")
                get_health_mock.assert_called_once_with(b"ok")
                json_dumps_mock.assert_called_once()

    # Test the thirteenth condition
    with patch.object(DapiMock, "add_request") as add_request_mock:
        assert master_handler.process_request(command=b'sendsync', data=b"data") == (b'ok',
                                                                                     b'Added request to SendSync '
                                                                                     b'requests queue')
        add_request_mock.assert_called_once_with(master_handler.name.encode() + b"*" + b"data")

    # Test the fourteenth condition
    with patch("wazuh.core.cluster.server.AbstractServerHandler.process_request",
               return_value=b"ok") as process_request_mock:
        assert master_handler.process_request(command=b'random', data=b"data") == b"ok"
        process_request_mock.assert_called_once_with(b"random", b"data")

    logger_mock.assert_has_calls([call("Command received: b'syn_i_w_m_p'"), call("Command received: b'syn_a_w_m_p'"),
                                  call("Command received: b'syn_i_w_m'"), call("Command received: b'syn_e_w_m'"),
                                  call("Command received: b'syn_a_w_m'"), call("Command received: b'syn_i_w_m_e'"),
                                  call("Command received: b'syn_e_w_m_e'"), call("Command received: b'syn_i_w_m_r'"),
                                  call("Command received: b'syn_w_g_e'"), call("Command received: b'syn_wgc_e'"),
                                  call("Command received: b'syn_w_g_err'"), call("Command received: b'syn_wgc_err'"),
                                  call("Command received: b'dapi'"), call("Command received: b'dapi_res'"),
                                  call("Command received: b'get_nodes'"),
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

    async def await_event(fut: asyncio.Event, timeout):
        await fut

    async def unlock_event(event: asyncio.Event):
        event.set()
    
    master_handler.server = Server()

    wait_for_mock.side_effect = await_event
    event = asyncio.Event()
    dict_mock = MagicMock()
    d = {'Event': event, 'Response':''}
    dict_mock.__getitem__.return_value = d
    dict_mock.__setitem__.side_effect = lambda k, v: None
    master_handler.server.pending_api_requests = dict_mock
    # Test the first and second if
    with patch.object(LocalServer, "send_request", return_value=b"ok") as send_request_mock:
        return_values = await asyncio.gather(
            master_handler.execute(command=b'dapi_fwd', data=b"client request", wait_for_complete=True), 
            unlock_event(event))
        send_request_mock.assert_called_once_with(b"dapi", str(uuid4_mock.return_value).encode() + b' ' + b"request")
        assert return_values[0] == ''

    # Test the first elif and first try with a timeout
    with patch("wazuh.core.cluster.master.MasterHandler.send_request", return_value=b"result") as send_request_mock:
        assert await master_handler.execute(command=b'dapi', data=b"client request", wait_for_complete=False) == ""
        send_request_mock.assert_called_once_with(b"dapi",
                                                  str(uuid4_mock.return_value).encode() + b' ' + b"client request")

    # Test the first and second else
    with patch("wazuh.core.cluster.master.MasterHandler.process_request",
               return_value=[b"ok", b""]) as process_request_mock:
        return_values = await asyncio.gather(
            master_handler.execute(command=b'random', data=b"client request", wait_for_complete=True),
            unlock_event(event))
        process_request_mock.assert_called_once_with(command=b"random", data=b"client request")
        assert return_values[0] == ''

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
    master_handler.cluster_items['intervals']['communication']['timeout_dapi_request'] = 0.1
    with patch("wazuh.core.cluster.master.MasterHandler.send_request", return_value=b"result"):
        with pytest.raises(exception.WazuhClusterError, match=r".* 3021 .*"):
            await master_handler.execute(command=b'dapi', data=b"client request", wait_for_complete=False)

    # Test the third exception
    with patch("wazuh.core.cluster.master.MasterHandler.process_request", return_value=[b"error", b""]):
        with pytest.raises(exception.WazuhClusterError, match=r".* 3022 .*"):
            await master_handler.execute(command=b'random', data=b"client request", wait_for_complete=True)


@patch("wazuh.core.cluster.master.AsyncWazuhDBConnection")
@patch("wazuh.core.cluster.common.SyncWazuhdb", return_value="SyncWazuhdbMock")
@patch("wazuh.core.cluster.common.SyncFiles", return_value="SyncFilesMock")
@patch("os.path.exists", return_value=False)
@patch("os.path.join", return_value="/some/path")
@patch("wazuh.core.cluster.master.utils.mkdir_with_mode")
@patch("wazuh.core.cluster.master.metadata.__version__", "version")
@patch("wazuh.core.cluster.server.AbstractServerHandler.hello", return_value=(b"ok", "payload"))
def test_master_handler_hello_ok(super_hello_mock, mkdir_with_mode_mock, join_mock, path_exists_mock, sync_files_mock,
                                 sync_db_mock, mock_db_conn):
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
    join_mock.assert_called_once_with(common.WAZUH_PATH, "queue", "cluster", None)
    path_exists_mock.assert_called_once_with("/some/path")
    sync_files_mock.assert_called_once_with(cmd=b"syn_m_c", logger=ANY, manager=ANY)
    sync_db_mock.assert_called_once_with(manager=ANY, logger=ANY, cmd=b"syn_g_m_w", data_retriever=ANY,
                                         set_data_command="global set-agent-groups",
                                         set_payload={"mode": "override", "sync_status": "synced"})

    assert "Integrity check" in master_handler.task_loggers
    assert "Integrity sync" in master_handler.task_loggers
    assert "Agent-info sync" in master_handler.task_loggers

    assert isinstance(master_handler.task_loggers["Integrity check"], logging.Logger)
    assert isinstance(master_handler.task_loggers["Integrity sync"], logging.Logger)
    assert isinstance(master_handler.task_loggers["Agent-info sync"], logging.Logger)

    assert master_handler.version == "version"
    assert master_handler.cluster_name == "cluster_name"
    assert master_handler.node_type == "node_type"
    assert master_handler.integrity == "SyncFilesMock"
    assert master_handler.agent_groups == "SyncWazuhdbMock"


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

@pytest.mark.asyncio
async def test_master_handler_process_dapi_res_ok():
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
    with patch.object(master_handler, "forward_dapi_response", return_value=True) as forward_dapi_response_mock:
        assert master_handler.process_dapi_res(b"req_id string_id") == (b'ok', b'Response forwarded to worker')
        while forward_dapi_response_mock.called == False:
            asyncio.sleep(0.01)

        forward_dapi_response_mock.assert_called()


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

    class MockServer:
        """Auxiliar class."""

        def __init__(self):
            self.integrity_already_executed = ['not wazuh']

    master_handler = get_master_handler()
    master_handler.server = MockServer()
    master_handler.name = 'wazuh'
    master_handler.sync_integrity_free[0] = False

    # Test the first condition
    assert master_handler.get_permission(b'syn_i_w_m_p') == (b"ok", str(master_handler.sync_integrity_free[0]).encode())

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
    assert master_handler.sync_integrity_free[0] is False
    assert isinstance(master_handler.sync_integrity_free[1], datetime)

    # Test the second condition
    assert master_handler.setup_sync_integrity(b'syn_e_w_m', b"data") == b"ok"

    # Test the third condition
    assert master_handler.setup_sync_integrity(b'syn_a_w_m', b"data") == b"ok"
    assert master_handler.sync_agent_info_free is False

    # Test the fourth condition
    assert master_handler.setup_sync_integrity(b'random', b"data") == b"ok"

    setup_receive_file_mock.assert_has_calls([
        call(receive_task_class=master.ReceiveIntegrityTask, data=b'data', logger_tag='Integrity check'),
        call(receive_task_class=master.ReceiveExtraValidTask, data=b'data', logger_tag='Integrity sync'),
        call(receive_task_class=master.ReceiveAgentInfoTask, data=b'data', logger_tag='Agent-info sync'),
        call(receive_task_class=None, data=b'data', logger_tag='')
    ])


@patch("wazuh.core.cluster.common.WazuhCommon.setup_send_info", return_value=b"ok")
def test_master_handler_setup_send_info(setup_receive_file_mock):
    """Check if the send process was correctly started."""

    master_handler = get_master_handler()

    # Test the first condition
    assert master_handler.setup_send_info(b'syn_w_g_c') == b"ok"

    # Test the second condition
    assert master_handler.setup_send_info(b'NONE') == b"ok"

    setup_receive_file_mock.assert_has_calls([
        call(send_task_class=master.SendEntireAgentGroupsTask, logger_tag='Agent-groups send full'),
        call(send_task_class=None, logger_tag='')
    ])

@patch("wazuh.core.cluster.common.WazuhCommon.error_receiving_file", return_value=b"ok")
def test_master_handler_process_sync_error_from_worker(error_receiving_file_mock):
    """Check if an error is properly managed when it takes place."""
    master_handler = get_master_handler()
    assert master_handler.process_sync_error_from_worker(b"error") == b"ok"
    assert master_handler.sync_integrity_free[0] is True
    assert isinstance(master_handler.sync_integrity_free[1], datetime)
    error_receiving_file_mock.assert_called_once_with(task_id_and_error_details='error', logger_tag='Integrity sync')


@patch("wazuh.core.cluster.common.WazuhCommon.end_receiving_file", return_value=b"ok")
def test_master_handler_end_receiving_integrity_checksums(end_receiving_file_mock):
    """Check if the function is started after receiving a file."""

    assert get_master_handler().end_receiving_integrity_checksums("task_and_file_names") == b"ok"
    end_receiving_file_mock.assert_called_once_with(task_and_file_names='task_and_file_names',
                                                    logger_tag='Integrity check')


@pytest.mark.asyncio
@freeze_time('1970-01-01')
@patch('wazuh.core.cluster.common.Handler.send_request', return_value='some_data')
@patch('wazuh.core.cluster.common.Handler.update_chunks_wdb', return_value={'updated_chunks': 1})
@patch('wazuh.core.cluster.common.Handler.get_chunks_in_task_id', return_value='chunks')
async def test_master_handler_sync_wazuh_db_info(get_chunks_mock, update_chunks_mock, send_request_mock):
    """Check that the wazuh-db data reception task is created and chunks are obtained and updated in DB."""
    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._info = []

        def info(self, info):
            self._info.append(info)

    master_handler = get_master_handler()
    logger = LoggerMock()
    master_handler.task_loggers['Agent-info sync'] = logger
    master_handler.sync_agent_info_status = {'n_synced_chunks': 0}

    assert await master_handler.sync_wazuh_db_info(task_id=b'17', info_type='agent-groups') == 'some_data'
    get_chunks_mock.assert_called_once_with(b'17', b'syn_m_a_err')
    update_chunks_mock.assert_called_once_with('chunks', 'agent-info', logger, b'syn_m_a_err', 0)
    send_request_mock.assert_called_once_with(command=b'syn_m_a_e', data=b'{"updated_chunks": 1}')
    assert logger._info == ['Starting.', 'Finished in 0.000s. Updated 1 chunks.']
    assert master_handler.sync_agent_info_status == {'n_synced_chunks': 1,
                                                     'date_start_master': '1970-01-01T00:00:00.000000Z',
                                                     'date_end_master': '1970-01-01T00:00:00.000000Z'}


@pytest.mark.asyncio
@patch("wazuh.core.cluster.master.MasterHandler.recalculate_group_hash", return_value=AsyncMock())
@patch('wazuh.core.cluster.common.SyncWazuhdb')
async def test_manager_handler_send_entire_agent_groups_information(syncwazuhdb_mock, recalculate_group_hash_mock):
    """Check if the data chunks are being properly forward to the Wazuh-db socket."""

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._debug = []
            self._info = []
            self._error = []

        def info(self, data):
            """Auxiliary method."""
            self._info.append(data)

    master_handler = get_master_handler()
    logger = LoggerMock()
    master_handler.task_loggers["Agent-groups send full"] = logger
    syncwazuhdb_mock.return_value.retrieve_information = AsyncMock()
    syncwazuhdb_mock.return_value.sync = AsyncMock()
    assert await master_handler.send_entire_agent_groups_information() is None
    syncwazuhdb_mock.assert_called_once_with(manager=master_handler, logger=logger, cmd=b'syn_g_m_w_c',
                                             data_retriever=ANY,
                                             get_data_command='global sync-agent-groups-get ',
                                             get_payload={'condition': 'all', 'set_synced': False,
                                                          'get_global_hash': False, 'last_id': 0},
                                             pivot_key='last_id', set_data_command='global set-agent-groups',
                                             set_payload={'mode': 'override', 'sync_status': 'synced'})
    syncwazuhdb_mock.return_value.retrieve_information.assert_called_once()
    syncwazuhdb_mock.return_value.sync.assert_called_once_with(start_time=ANY, chunks=ANY)
    assert logger._info == ['Starting.']


@pytest.mark.asyncio
@patch("wazuh.core.cluster.master.AsyncWazuhDBConnection")
async def test_manager_handler_send_agent_groups_information(asyncwazuhdbconnection_mock):
    """Check if the data chunks are being properly forward to the Wazuh-db socket."""

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._info = []
            self._error = []

        def info(self, data):
            """Auxiliary method."""
            self._info.append(data)

        def error(self, data, exc_info=False):
            """Auxiliary method."""
            self._error.append(data)

    master_handler = get_master_handler()
    master_handler.name = "worker_test"
    master_handler.task_loggers["Agent-groups send"] = LoggerMock()
    master_handler.agent_groups = MagicMock()

    await master_handler.send_agent_groups_information("test_info")
    master_handler.agent_groups.sync.assert_called_once_with(
        start_time=master_handler.send_agent_groups_status["date_start"], chunks="test_info")

    assert master_handler.task_loggers["Agent-groups send"]._info == ['Starting.']
    assert master_handler.task_loggers["Agent-groups send"]._error == [
        "Error sending agent-groups information to worker_test: object MagicMock can't be used in 'await' expression"]


@pytest.mark.asyncio
@patch("shutil.rmtree")
@patch("asyncio.wait_for")
@patch("wazuh.core.cluster.cluster.decompress_files", return_value=("files_metadata", "/decompressed/files/path"))
@patch('wazuh.core.cluster.master.cluster.run_in_pool',
       return_value={'total_updated': 0, 'errors_per_folder': {'key': 'value'}, 'generic_errors': ['ERR']})
async def test_master_handler_sync_worker_files_ok(run_in_pool_mock, decompress_files_mock, wait_for_mock, rmtree_mock):
    """Check if the extra_valid files are properly received and processed."""

    class TaskMock:
        """Auxiliary class."""

        def __init__(self):
            self.filename = "filename"

    class ServerMock:
        """Auxiliary class."""

        def __init__(self):
            self.integrity_control = True
            self.task_pool = ''

    async def await_event(fut: asyncio.Event, timeout):
        await fut

    async def unlock_event(event: asyncio.Event):
        event.set()
    
    wait_for_mock.side_effect = await_event

    master_handler = get_master_handler()
    master_handler.sync_tasks["task_id"] = TaskMock()
    master_handler.server = ServerMock()

    # await for sync_worker_files and unlock_event to complete. unlock_event unblocs Event.wait()
    event = asyncio.Event()
    await asyncio.gather(
        master_handler.sync_worker_files("task_id", event, logging.getLogger("wazuh")),
        unlock_event(event))
    wait_for_mock.assert_awaited_once()
    decompress_files_mock.assert_called_once()
    rmtree_mock.assert_called_once_with("/decompressed/files/path")
    run_in_pool_mock.assert_awaited_once_with(master_handler.loop, master_handler.server.task_pool,
                                             master_handler.process_files_from_worker,
                                             decompress_files_mock.return_value[0],
                                             decompress_files_mock.return_value[1], master_handler.cluster_items,
                                             master_handler.name,
                                             master_handler.cluster_items['intervals']['master']['timeout_extra_valid'])


@pytest.mark.asyncio
@patch("shutil.rmtree")
@patch('wazuh.core.cluster.master.cluster.run_in_pool', side_effect=Exception)
@patch("wazuh.core.cluster.cluster.decompress_files", return_value=("files_metadata", "/decompressed/files/path"))
@patch("wazuh.core.cluster.master.MasterHandler.wait_for_file")
async def test_master_handler_sync_worker_files_ko(wait_for_mock, decompress_files_mock, run_in_pool_mock, rmtree_mock):
    """Check if the exceptions are properly raised."""

    class TaskMock:
        """Auxiliary class."""

        def __init__(self):
            self.filename = Exception()

    master_handler = get_master_handler()
    master_handler.sync_tasks["task_id"] = TaskMock()

    #  Test the first exception
    with pytest.raises(Exception):
        await master_handler.sync_worker_files("task_id", asyncio.Event(), logging.getLogger("wazuh"))

    # Test the second exception
    with pytest.raises(exception.WazuhClusterError, match=r'.* 3038 .*'):
        master_handler.sync_tasks["task_id"].filename = ''
        await master_handler.sync_worker_files("task_id", asyncio.Event(), logging.getLogger("wazuh"))

    decompress_files_mock.assert_called_once_with('', 'files_metadata.json')
    run_in_pool_mock.assert_not_called()
    rmtree_mock.assert_called_once_with(decompress_files_mock.return_value[1])


@pytest.mark.asyncio
@patch("wazuh.core.cluster.master.MasterHandler.set_date_end_master")
@patch("wazuh.core.cluster.master.MasterHandler.sync_worker_files")
async def test_master_handler_sync_extra_valid(sync_worker_files_mock, set_date_end_master_mock):
    """Check if the extra_valid sync process is properly run."""
    master_handler = get_master_handler()
    master_handler.task_loggers["Integrity sync"] = logging.getLogger("wazuh")
    await master_handler.sync_extra_valid("task_id", None)

    sync_worker_files_mock.assert_called_once_with("task_id", None, logging.getLogger("wazuh"))
    set_date_end_master_mock.assert_called_once_with(logging.getLogger("wazuh"))
    assert master_handler.integrity_sync_status['date_end_master'] == DEFAULT_DATE
    assert master_handler.integrity_sync_status['date_start_master'] == DEFAULT_DATE
    assert master_handler.extra_valid_requested is False
    assert master_handler.sync_integrity_free[0] is True
    assert isinstance(master_handler.sync_integrity_free[1], datetime)


@freeze_time("1970-01-01")
@patch.object(logging.getLogger("wazuh"), "info")
def test_set_date_end_master(info_mock):
    """Check if set_date_end_master works as expected."""
    master_handler = get_master_handler()
    master_handler.integrity_sync_status['tmp_date_start_master'] = datetime.utcnow().replace(tzinfo=timezone.utc)
    master_handler.set_date_end_master(logging.getLogger("wazuh"))

    assert master_handler.integrity_sync_status['date_end_master'] == "1970-01-01T00:00:00.000000Z"
    assert isinstance(master_handler.integrity_sync_status['date_start_master'], str)
    assert isinstance(master_handler.integrity_sync_status['date_end_master'], str)
    info_mock.assert_called_once()


@pytest.mark.parametrize('compare_result', [
    {}, {'test': 'test'}
])
@pytest.mark.asyncio
@freeze_time("2021-11-02")
@patch("shutil.rmtree")
@patch.object(logging.getLogger("wazuh"), "info")
@patch.object(logging.getLogger("wazuh"), "debug")
@patch("wazuh.core.cluster.master.MasterHandler.integrity_sync")
@patch("wazuh.core.cluster.master.MasterHandler.wait_for_file")
@patch("wazuh.core.cluster.master.MasterHandler.send_request", return_value=b"ok")
@patch("wazuh.core.cluster.cluster.decompress_files", return_value=("files_metadata", "/decompressed/files/path"))
async def test_master_handler_integrity_check(decompress_files_mock, send_request_mock, wait_for_file_mock,
                                              integrity_sync_mock, debug_mock, info_mock, rmtree_mock, compare_result):
    """Test if the comparison between the local and received files is properly done."""

    class TaskMock:
        """Auxiliary class."""

        def __init__(self):
            self.filename = "filename"

    class EventMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        async def wait(self):
            """Auxiliary method."""
            pass

    class ServerMock:
        """Auxiliary class."""

        def __init__(self):
            self.integrity_control = True
            self.task_pool = ''

    master_handler = get_master_handler()
    master_handler.server = ServerMock()
    master_handler.sync_tasks = {"task_id": TaskMock()}
    master_handler.task_loggers["Integrity check"] = logging.getLogger("wazuh")

    with patch("wazuh.core.cluster.cluster.compare_files", return_value=({"extra_valid": compare_result})
               ) as compare_mock:
        assert await master_handler.integrity_check("task_id", EventMock()) is None
        debug_mock.assert_called_once_with("Received file from worker: 'filename'")
        decompress_files_mock.assert_called_once_with('filename', 'files_metadata.json')
        compare_mock.assert_called_once_with(True, 'files_metadata', None)
        wait_for_file_mock.assert_called_once_with(file=ANY, task_id='task_id')
        rmtree_mock.assert_called_once_with('/decompressed/files/path')
        assert master_handler.integrity_check_status == {'date_start_master': '2021-11-02T00:00:00.000000Z',
                                                         'date_end_master': '2021-11-02T00:00:00.000000Z'}
        if compare_result:
            integrity_sync_mock.assert_called_once_with({"extra_valid": compare_result})
            assert info_mock.call_args_list == [call('Starting.'), call('Finished in 0.000s. Received metadata '
                                                                        'of 14 files. Sync required.')]
        else:
            send_request_mock.assert_called_once_with(command=b'syn_m_c_ok', data=b'')
            assert info_mock.call_args_list == [call('Starting.'),  call('Finished in 0.000s. Received metadata '
                                                                         'of 14 files. Sync not required.')]


@pytest.mark.asyncio
@patch("wazuh.core.cluster.master.MasterHandler.wait_for_file", return_value=Exception())
async def test_master_handler_integrity_check_ko(wait_for_file_mock):
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
        await master_handler.integrity_check("task_id", EventMock())


@pytest.mark.asyncio
@freeze_time("2021-11-02")
@patch.object(logging.getLogger("wazuh"), "info")
@patch("wazuh.core.cluster.master.MasterHandler.set_date_end_master")
async def test_master_handler_integrity_sync(set_date_end_mock, info_mock):
    """Test if expected methods are called inside integrity_sync."""
    class ServerMock:
        """Auxiliary class."""

        def __init__(self):
            self.integrity_control = True
            self.task_pool = None

    master_handler = get_master_handler()
    master_handler.integrity = AsyncMock()
    master_handler.current_zip_limit = 1000
    master_handler.server = ServerMock()
    master_handler.task_loggers["Integrity sync"] = logging.getLogger("wazuh")

    await master_handler.integrity_sync({'missing': {'path': 'test'}, 'shared': {}, 'extra': {}, 'extra_valid': {}})
    assert master_handler.integrity_sync_status == {'date_start_master': ANY, 'tmp_date_start_master': ANY,
                                                    'date_end_master': ANY, 'total_extra_valid': 0,
                                                    'total_files': {'missing': 1, 'shared': 0, 'extra': 0,
                                                                    'extra_valid': 0}}
    master_handler.integrity.sync.assert_called_once_with(
        {'path'}, {'missing': {'path': 'test'}, 'shared': {}, 'extra': {}, 'extra_valid': {}}, 1, None, 1000)
    assert info_mock.call_args_list == [call('Starting.'),
                                        call('Files to create in worker: 1 | Files to update in worker: 0 | '
                                             'Files to delete in worker: 0')]
    set_date_end_mock.assert_called_once()


@freeze_time("1970-01-01")
@patch("os.path.join", return_value="/some/path")
@patch('wazuh.core.cluster.master.utils.safe_move')
@patch("os.path.basename", return_value="client.keys")
@patch("wazuh.core.common.wazuh_uid", return_value="wazuh_uid")
@patch("wazuh.core.common.wazuh_gid", return_value="wazuh_gid")
def test_master_handler_process_files_from_worker_ok(gid_mock, uid_mock, basename_mock, safe_move_mock, path_join_mock):
    """Check if the local files are updated and the received iterated over."""

    master_handler = get_master_handler()
    files_metadata = {
        "data": {"merged": "1", "merge_type": "type", "merge_name": "name", "cluster_item_key": "queue/testing/"}}

    class StatMock:
        """Auxiliary class."""

        def __init__(self):
            self.st_mtime = "20"

    def reset_mock(data):
        """Auxiliary method."""
        for mock in data:
            mock.reset_mock()

    all_mocks = [basename_mock, path_join_mock]
    decompressed_files_path = '/decompressed/files/path'
    worker_name = 'wazuh'
    timeout = 0

    # Test the first and second try
    # Nested function: try -> 1º if and 2º exception
    result = master_handler.process_files_from_worker(files_metadata=files_metadata,
                                                      decompressed_files_path=decompressed_files_path,
                                                      cluster_items=cluster_items, worker_name=worker_name,
                                                      timeout=timeout)

    basename_mock.assert_called_with('data')
    path_join_mock.assert_called_once_with(common.WAZUH_PATH, "data")
    assert result == {'total_updated': 0, 'errors_per_folder': defaultdict(list), 'generic_errors':
                      ["Error updating worker files (extra valid): 'Error 3007 - Client.keys file received in master node'."]}

    # Reset all the used mocks
    reset_mock(all_mocks)

    basename_mock.return_value = "/os/path/basename"
    with patch("wazuh.core.cluster.cluster.unmerge_info",
               return_value=[("/file/path", "file data", '1970-01-01 00:00:00.000+00:00')]) as unmerge_info_mock:
        with patch('os.path.isfile', return_value=True) as isfile_mock:
            with patch('os.stat', return_value=StatMock()) as os_stas_mock:
                # Test until the 'continue'
                result = master_handler.process_files_from_worker(files_metadata=files_metadata,
                                                                  decompressed_files_path=decompressed_files_path,
                                                                  cluster_items=cluster_items, worker_name=worker_name,
                                                                  timeout=timeout)

                basename_mock.assert_has_calls([call('data'), call('/file/path')])
                path_join_mock.assert_has_calls([call(common.WAZUH_PATH, 'data'),
                                                 call(common.WAZUH_PATH, '/file/path'),
                                                 call(common.WAZUH_PATH, 'queue', 'cluster', 'wazuh',
                                                      '/os/path/basename')])
                unmerge_info_mock.assert_called_once_with('type', decompressed_files_path, 'name')
                assert result == {'total_updated': 0, 'errors_per_folder': defaultdict(list), 'generic_errors': []}
                isfile_mock.assert_called_once_with(path_join_mock.return_value)
                os_stas_mock.assert_called_once_with(path_join_mock.return_value)

                # Reset all the used mocks
                all_mocks += [unmerge_info_mock, isfile_mock, os_stas_mock]
                reset_mock(all_mocks)

                # Test until the 'continue'
                unmerge_info_mock.return_value = [("/file/path", "file data", '1970-01-01 00:00:00+00:00')]
                result = master_handler.process_files_from_worker(files_metadata=files_metadata,
                                                                  decompressed_files_path=decompressed_files_path,
                                                                  cluster_items=cluster_items, worker_name=worker_name,
                                                                  timeout=timeout)

                basename_mock.assert_has_calls([call('data'), call('/file/path')])
                path_join_mock.assert_has_calls([call(common.WAZUH_PATH, 'data'),
                                                 call(common.WAZUH_PATH, '/file/path'),
                                                 call(common.WAZUH_PATH, 'queue', 'cluster', 'wazuh',
                                                      '/os/path/basename')])
                unmerge_info_mock.assert_called_once_with('type', decompressed_files_path, 'name')
                assert result == {'total_updated': 0, 'errors_per_folder': defaultdict(list), 'generic_errors': []}
                isfile_mock.assert_called_once_with(path_join_mock.return_value)
                os_stas_mock.assert_called_once_with(path_join_mock.return_value)

                # Reset all the used mocks
                all_mocks += [unmerge_info_mock, isfile_mock, os_stas_mock]
                reset_mock(all_mocks)

            # Test after the 'continue'
            isfile_mock.return_value = False

            with patch('builtins.open'):
                result = master_handler.process_files_from_worker(files_metadata=files_metadata,
                                                                  decompressed_files_path=decompressed_files_path,
                                                                  cluster_items=cluster_items,
                                                                  worker_name=worker_name,
                                                                  timeout=timeout)

                assert result == {'errors_per_folder': defaultdict(list, {'queue/testing/': ["'queue/testing/'"]}),
                                  'generic_errors': [], 'total_updated': 0}
                basename_mock.assert_has_calls([call('data'), call('/file/path')])
                path_join_mock.assert_has_calls([call(common.WAZUH_PATH, 'data'),
                                                 call(common.WAZUH_PATH, '/file/path'),
                                                 call(common.WAZUH_PATH, 'queue', 'cluster', 'wazuh',
                                                      '/os/path/basename')])
                unmerge_info_mock.assert_called_once_with('type', decompressed_files_path, 'name')
                isfile_mock.assert_called_once_with(path_join_mock.return_value)
                gid_mock.assert_called_once_with()
                uid_mock.assert_called_once_with()

                # Reset all the used mocks
                all_mocks += [gid_mock, uid_mock, safe_move_mock]
                reset_mock(all_mocks)

            # Test the Timeout
            isfile_mock.side_effect = TimeoutError
            result = master_handler.process_files_from_worker(files_metadata=files_metadata,
                                                              decompressed_files_path=decompressed_files_path,
                                                              cluster_items=cluster_items,
                                                              worker_name=worker_name,
                                                              timeout=timeout)

            assert result == {'total_updated': 0, 'errors_per_folder': defaultdict(list),
                              'generic_errors': ['Timeout processing extra-valid files.']}

            # Test the Except present in the second if
            isfile_mock.side_effect = Exception
            result = master_handler.process_files_from_worker(files_metadata=files_metadata,
                                                              decompressed_files_path=decompressed_files_path,
                                                              cluster_items=cluster_items,
                                                              worker_name=worker_name,
                                                              timeout=timeout)

            assert result == {'total_updated': 0, 'errors_per_folder': defaultdict(list, {'queue/testing/': ['']}),
                              'generic_errors': []}

    # Test the else
    files_metadata['data']['merged'] = None
    reset_mock(all_mocks)

    result = master_handler.process_files_from_worker(files_metadata=files_metadata,
                                                      decompressed_files_path=decompressed_files_path,
                                                      cluster_items=cluster_items,
                                                      worker_name=worker_name,
                                                      timeout=timeout)

    assert result == {'errors_per_folder': defaultdict(list, {'queue/testing/': ["'queue/testing/'"]}),
                      'generic_errors': [], 'total_updated': 0}
    path_join_mock.assert_has_calls([call(common.WAZUH_PATH, 'data'),
                                     call(decompressed_files_path, 'data')])

    safe_move_mock.side_effect = TimeoutError
    result = master_handler.process_files_from_worker(files_metadata=files_metadata,
                                                      decompressed_files_path=decompressed_files_path,
                                                      cluster_items=cluster_items,
                                                      worker_name=worker_name,
                                                      timeout=timeout)

    assert result == {'errors_per_folder': defaultdict(list, {'queue/testing/': ["'queue/testing/'"]}),
                      'generic_errors': [], 'total_updated': 0}

    safe_move_mock.side_effect = Exception
    result = master_handler.process_files_from_worker(files_metadata=files_metadata,
                                                      decompressed_files_path=decompressed_files_path,
                                                      cluster_items=cluster_items,
                                                      worker_name=worker_name,
                                                      timeout=timeout)

    assert result == {'errors_per_folder': defaultdict(list, {'queue/testing/': ["'queue/testing/'"]}),
                      'generic_errors': [], 'total_updated': 0}


def test_master_handler_get_logger():
    """Check if the right Logger object is being returned."""

    master_handler = get_master_handler()

    # Test the first if
    assert master_handler.get_logger() == master_handler.logger
    assert "random_tag" not in master_handler.task_loggers

    master_handler.task_loggers["random_tag"] = "output"
    assert master_handler.get_logger("random_tag") == "output"


@pytest.mark.parametrize('worker_name', [
    'worker1',
    ''
])
@patch.object(logging.getLogger("wazuh"), "info")
@patch("wazuh.core.cluster.master.server.AbstractServerHandler.connection_lost")
@patch("wazuh.core.cluster.master.cluster.clean_up") 
def test_master_handler_connection_lost(clean_up_mock, connection_lost_mock, logger_mock, worker_name):
    """Check if all the pending tasks are closed when the connection between workers and master is lost."""

    master_handler = get_master_handler()
    master_handler.logger = logging.getLogger("wazuh")
    master_handler.name = worker_name

    class PendingTaskMock:
        """Auxiliary class."""

        def __init__(self):
            self.task = TaskMock()

    class TaskMock:
        """Auxiliary class."""

        def __init__(self):
            self.cancel_called = False

        def cancel(self):
            """Auxiliary method."""
            self.cancel_called = True

    master_handler.sync_tasks = {"key": PendingTaskMock()}
    master_handler.connection_lost(Exception())

    for pending_task_mock in master_handler.sync_tasks.values():
        assert pending_task_mock.task.cancel_called

    connection_lost_mock.assert_called_once()
    if worker_name:
        clean_up_mock.assert_called_once_with(node_name=worker_name)
    else:
        clean_up_mock.assert_not_called()


# Test Master class


@patch.object(logging.getLogger("wazuh"), "warning")
@patch('asyncio.get_running_loop', return_value=loop)
@patch("wazuh.core.cluster.master.ProcessPoolExecutor")
def test_master_init(pool_executor_mock, get_running_loop_mock, warning_mock):
    """Check if the Master class is being properly initialized."""

    class PoolExecutorMock:
        def __init__(self, max_workers):
            pass

    # Test the try
    pool_executor_mock.return_value = PoolExecutorMock

    master_class = master.Master(performance_test=False, concurrency_test=False,
                                 configuration={'node_name': 'master', 'nodes': ['master'], 'port': 1111},
                                 cluster_items=cluster_items,
                                 enable_ssl=False)

    assert master_class.integrity_control == {}
    assert master_class.handler_class == master.MasterHandler
    assert master_class.integrity_already_executed == []
    assert master_class.task_pool == PoolExecutorMock
    assert master_class.integrity_already_executed == []
    assert isinstance(master_class.dapi, dapi.APIRequestQueue)
    assert isinstance(master_class.sendsync, dapi.SendSyncRequestQueue)
    assert master_class.dapi.run in master_class.tasks
    assert master_class.sendsync.run in master_class.tasks
    assert master_class.file_status_update in master_class.tasks
    assert master_class.pending_api_requests == {}

    # Test the exceptions
    pool_executor_mock.side_effect = FileNotFoundError
    master_class = master.Master(performance_test=False, concurrency_test=False,
                                 configuration={'node_name': 'master', 'nodes': ['master'], 'port': 1111},
                                 cluster_items=cluster_items,
                                 enable_ssl=False)

    warning_mock.assert_has_calls([call("In order to take advantage of Wazuh 4.3.0 cluster improvements, the directory "
                                        "'/dev/shm' must be accessible by the 'wazuh' user. Check that this file has "
                                        "permissions to be accessed by all users. Changing the file permissions to 777 "
                                        "will solve this issue."),
                                   call('The Wazuh cluster will be run without the improvements added in Wazuh 4.3.0 '
                                        'and higher versions.')])

    pool_executor_mock.side_effect = PermissionError
    master_class = master.Master(performance_test=False, concurrency_test=False,
                                 configuration={'node_name': 'master', 'nodes': ['master'], 'port': 1111},
                                 cluster_items=cluster_items,
                                 enable_ssl=False)

    warning_mock.assert_has_calls([call("In order to take advantage of Wazuh 4.3.0 cluster improvements, the directory "
                                        "'/dev/shm' must be accessible by the 'wazuh' user. Check that this file has "
                                        "permissions to be accessed by all users. Changing the file permissions to 777 "
                                        "will solve this issue."),
                                   call('The Wazuh cluster will be run without the improvements added in Wazuh 4.3.0 '
                                        'and higher versions.')])


@patch('asyncio.get_running_loop', return_value=loop)
@patch("wazuh.core.cluster.master.metadata.__version__", "1.0.0")
def test_master_to_dict(get_running_loop_mock):
    """Check if the master's healthcheck information is properly obtained."""

    master_class = master.Master(performance_test=False, concurrency_test=False,
                                 configuration={'node_name': 'master', 'nodes': ['master'], 'port': 1111,
                                                "node_type": "master"},
                                 cluster_items=cluster_items,
                                 enable_ssl=False)

    assert master_class.to_dict() == {
        'info': {'name': master_class.configuration['node_name'], 'type': master_class.configuration['node_type'],
                 'version': "1.0.0", 'ip': master_class.configuration['nodes'][0]}}


@pytest.mark.asyncio
@freeze_time("2022-01-01")
@patch('wazuh.core.cluster.master.perf_counter', return_value=0)
@patch('asyncio.sleep')
async def test_agent_groups_update(sleep_mock, perf_counter_mock):
    """Check that agent-groups information is periodically retrieved from the database."""

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._info = []
            self._error = []
            self.counter = 0

        def info(self, data):
            """Auxiliary method."""
            self._info.append(data)
            self.counter += 1
            if self.counter >= 5:
                raise Exception('Stop while true')

        def error(self, data):
            """Auxiliary method."""
            self._error.append(data)
            raise Exception('Stop while true')

    class AsyncWazuhDBConnectionMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        async def run_wdb_command(self):
            pass

    class SyncWazuhdbMock:
        """Auxiliary class."""

        def __init__(self, manager, logger, cmd, data_retriever, get_data_command, get_payload):
            self.counter = 0
            self.logger = logger

        async def retrieve_information(self):
            """Auxiliary method."""
            self.counter += 1
            if self.counter >= 2:
                raise Exception('Testing')
            return ['[{"data":[]}]']

    logger_mock = LoggerMock()
    master_class = get_master()

    with patch("wazuh.core.cluster.master.Master.setup_task_logger",
               return_value=logger_mock) as setup_task_logger_mock:
        with patch('wazuh.core.cluster.master.AsyncWazuhDBConnection', AsyncWazuhDBConnectionMock):
            with patch('wazuh.core.cluster.master.c_common.SyncWazuhdb', SyncWazuhdbMock):
                with pytest.raises(Exception, match='Stop while true'):
                    master_class.clients = {'worker1': 'worker1'}
                    await master_class.agent_groups_update()
                assert "Starting." in logger_mock._info
                assert "Finished in 0.000s." in logger_mock._info
                assert "Error getting agent-groups from WDB: Testing" in logger_mock._error
                setup_task_logger_mock.assert_called_once_with('Local agent-groups')

                with pytest.raises(Exception, match='Stop while true'):
                    logger_mock.counter = 0
                    master_class.clients = {}
                    await master_class.agent_groups_update()
                assert "No clients connected. Skipping." in logger_mock._info


@pytest.mark.asyncio
@freeze_time("2021-11-02")
@patch('asyncio.sleep')
async def test_master_file_status_update_ok(sleep_mock):
    """Check if the file status is properly obtained."""

    master_class = get_master()

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._info = []
            self._error = []
            self.counter = 0

        def info(self, data):
            """Auxiliary method."""
            self._info.append(data)

        def error(self, data):
            """Auxiliary method."""
            self._error.append(data)
            self.counter += 1
            if self.counter >= 2:
                raise Exception("Stop while true")

    counter = 0

    async def run_in_pool(loop, pool, f, *args, **kwargs):
        nonlocal counter
        counter += 1
        if counter >= 2:
            raise Exception('Stop run_in_pool')

        return ['info']

    logger_mock = LoggerMock()

    with patch("wazuh.core.cluster.master.cluster.run_in_pool", side_effect=run_in_pool) as run_in_pool_mock:
        with patch("wazuh.core.cluster.master.Master.setup_task_logger",
                   return_value=logger_mock) as setup_task_logger_mock:
            with pytest.raises(Exception, match='Stop while true'):
                await master_class.file_status_update()

            assert "Starting." in logger_mock._info
            assert "Finished in 0.000s. Calculated metadata of 1 files." in logger_mock._info
            assert "Error calculating local file integrity: Stop run_in_pool" in logger_mock._error
            setup_task_logger_mock.assert_called_once_with('Local integrity')
            assert master_class.integrity_control == ['info']


@pytest.mark.asyncio
@freeze_time("2021-11-02")
@patch('asyncio.sleep')
@patch('wazuh.core.cluster.master.cluster.run_in_pool', return_value={})
async def test_master_file_status_update_ok(run_in_pool_mock, asyncio_sleep_mock):
    """Check if the file status is properly obtained."""

    master_class = master.Master(performance_test=False, concurrency_test=False,
                                 configuration={'node_name': 'master', 'nodes': ['master'], 'port': 1111,
                                                "node_type": "master"},
                                 cluster_items=cluster_items,
                                 enable_ssl=False)

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._info = []
            self._error = []

        def info(self, data):
            """Auxiliary method."""
            self._info.append(data)

        def error(self, data):
            """Auxiliary method."""
            self._error.append(data)

    class IntegrityExecutedMock:
        """Auxiliary class."""

        def __init__(self):
            self._clear = False

        def clear(self):
            self._clear = True

    async def sleep_mock(recalculate_integrity):
        raise Exception()

    logger_mock = LoggerMock()
    master_class.integrity_already_executed = IntegrityExecutedMock()
    asyncio_sleep_mock.side_effect = sleep_mock

    with patch("wazuh.core.cluster.master.Master.setup_task_logger",
               return_value=logger_mock) as setup_task_logger_mock:
        # Test the 'try'
        try:
            await master_class.file_status_update()
        except Exception:
            assert "Starting." in logger_mock._info
            assert "Finished in 0.000s. Calculated metadata of 0 files." in logger_mock._info
            setup_task_logger_mock.assert_called_once_with('Local integrity')
            assert master_class.integrity_control == run_in_pool_mock.return_value

        # Test the 'except'
        run_in_pool_mock.side_effect = Exception
        try:
            await master_class.file_status_update()
        except Exception:
            assert "Error calculating local file integrity: " in logger_mock._error


@patch('asyncio.get_running_loop', return_value=loop)
@patch("wazuh.core.agent.Agent.get_agents_overview", return_value={'totalItems': 5})
def test_master_get_health(get_running_loop_mock, get_agent_overview_mock):
    """Check if nodes and the synchronization information is properly obtained."""

    class MockDict(Dict):
        def __init__(self, kwargs):
            super().__init__(**kwargs)

        def to_dict(self):
            return {'info': {'type': 'worker'}, 'status': {'last_keep_alive': 0}}

    class MockMaster(master.Master):
        def to_dict(self):
            return {'testing': 'get_health', 'info': {'type': 'master'}}

    master_class = MockMaster(performance_test=False, concurrency_test=False,
                              configuration={'node_name': 'master', 'nodes': ['master'], 'port': 1111,
                                             'node_type': 'master'},
                              cluster_items=cluster_items, enable_ssl=False)
    master_class.clients = {'1': MockDict({'testing': 'dict'})}

    assert master_class.get_health({'jey': 'value', 'hoy': 'value'}) == {'n_connected_nodes': 0, 'nodes': {}}
    assert master_class.get_health(None) == {'n_connected_nodes': 1,
                                             'nodes': {'1': {'info': {'n_active_agents': 5, 'type': 'worker'},
                                                             'status':
                                                                 {'last_keep_alive': '1970-01-01T00:00:00.000000Z'}},
                                                       'master': {'testing': 'get_health',
                                                                  'info': {'type': 'master', 'n_active_agents': 5}}}}


@patch('asyncio.get_running_loop', return_value=loop)
def test_master_get_node(get_running_loop_mock):
    """Check if basic information about the node is being returned."""

    master_class = master.Master(performance_test=False, concurrency_test=False,
                                 configuration={'node_name': 'master', 'nodes': ['master'], 'port': 1111,
                                                "node_type": "master", "name": "master"},
                                 cluster_items=cluster_items,
                                 enable_ssl=False)

    assert master_class.get_node() == {'type': master_class.configuration['node_type'],
                                       'cluster': master_class.configuration['name'],
                                       'node': master_class.configuration['node_name']}
