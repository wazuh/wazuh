# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import json
import logging
import sys
from functools import partial
from collections import defaultdict
from unittest.mock import patch, MagicMock, AsyncMock, call, ANY
import datetime

import pytest
from wazuh.core.analysis import RulesetReloadResponse
from freezegun import freeze_time

import wazuh.core.exception as exception

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.core.cluster import client, worker, common as cluster_common
        from wazuh.core import common as core_common
        from wazuh.core.wdb import AsyncWazuhDBConnection

logger = logging.getLogger("wazuh")
cluster_items = {'node': 'master-node',
                 'intervals': {'worker': {'connection_retry': 1, "sync_integrity": 2, "timeout_agent_groups": 0,
                                          "sync_agent_info": 5, "sync_agent_groups": 5,
                                          "agent_groups_mismatch_limit": 5},
                               "communication": {"timeout_receiving_file": 1, "max_zip_size": 1000, "min_zip_size": 0,
                                                 "zip_limit_tolerance": 0.2, "timeout_cluster_request": 20}},
                 "files": {"cluster_item_key": {"remove_subdirs_if_empty": True, "permissions": "value"}}}
configuration = {'node_name': 'master', 'nodes': ['master'], 'port': 1111, "name": "wazuh", "node_type": "master"}


def get_worker_handler(loop):
    """Return the needed WorkerHandler object. This is an auxiliary method."""

    with patch('asyncio.get_running_loop', return_value=loop):
        abstract_client = client.AbstractClientManager(configuration=configuration,
                                                       cluster_items=cluster_items,
                                                       enable_ssl=False, performance_test=False, logger=None,
                                                       concurrency_test=False, file='None', string=20)

    return worker.WorkerHandler(cluster_name='Testing', node_type='master', version='4.0.0',
                                loop=loop, on_con_lost=None, name='Testing',
                                fernet_key='01234567891011121314151617181920', logger=logger,
                                manager=abstract_client, cluster_items=cluster_items)


def get_sync_wazuh_db(worker_handler):
    return cluster_common.SyncWazuhdb(worker_handler, logging.getLogger("wazuh"), cmd=b"cmd",
                                      get_data_command="get_command", set_data_command="set_command",
                                      data_retriever=None)


@pytest.mark.asyncio
async def test_rgit_init(event_loop):
    """Test the initialization of the ReceiveAgentGroupsTask object."""

    async def coro(task_id: str, data: str):
        return ''

    def return_coro():
        return coro

    with patch('wazuh.core.cluster.worker.ReceiveAgentGroupsTask.set_up_coro',
               side_effect=return_coro) as set_up_coro_mock:
        receive_agent_groups_task = worker.ReceiveAgentGroupsTask(wazuh_common=get_worker_handler(event_loop),
                                                                  logger=logging.getLogger("wazuh"), task_id="0101")
        assert isinstance(receive_agent_groups_task.wazuh_common, cluster_common.WazuhCommon)
        assert receive_agent_groups_task.task_id == "0101"
        set_up_coro_mock.assert_called_once()


@pytest.mark.asyncio
async def test_rgit_set_up_coro(event_loop):
    """Check if the function is called when the master sends its periodic agent-groups information."""

    with patch('wazuh.core.cluster.worker.WorkerHandler.recv_agent_groups_periodic_information',
               return_value='') as recv_agent_mock:
        receive_agent_groups_task = worker.ReceiveAgentGroupsTask(wazuh_common=get_worker_handler(event_loop),
                                                                  logger=logging.getLogger("wazuh"), task_id="0101")
        while not receive_agent_groups_task.task.done():
            await asyncio.sleep(0.01)

        assert receive_agent_groups_task.coro == recv_agent_mock


@pytest.mark.asyncio
async def test_rgcit_set_up_coro(event_loop):
    """Check if the function is called when the master sends its entire agent-groups information."""

    with patch('wazuh.core.cluster.worker.WorkerHandler.recv_agent_groups_entire_information',
               return_value='') as recv_agent_mock:
        receive_agent_groups_task = worker.ReceiveEntireAgentGroupsTask(wazuh_common=get_worker_handler(event_loop),
                                                                        logger=logging.getLogger("wazuh"),
                                                                        task_id="0101")
        while not receive_agent_groups_task.task.done():
            await asyncio.sleep(0.01)

        assert receive_agent_groups_task.coro == recv_agent_mock


@pytest.mark.asyncio
async def test_rgit_done_callback(event_loop):
    """Check if the agent-groups periodic synchronization process was correct."""

    with patch('wazuh.core.cluster.worker.WorkerHandler.recv_agent_groups_periodic_information',
               return_value='') as recv_agent_mock:
        receive_agent_groups_task = worker.ReceiveAgentGroupsTask(wazuh_common=get_worker_handler(event_loop),
                                                                  logger=logging.getLogger("wazuh"), task_id="0101")

        while not receive_agent_groups_task.task.done():
            await asyncio.sleep(0.01)
        recv_agent_mock.assert_awaited_once()
        assert receive_agent_groups_task.wazuh_common.sync_agent_groups_free is True


@pytest.mark.asyncio
async def test_rgcit_done_callback(event_loop):
    """Check if the agent-groups entire synchronization process was correct."""

    with patch('wazuh.core.cluster.worker.WorkerHandler.recv_agent_groups_entire_information',
               return_value='') as recv_agent_mock:
        receive_agent_groups_task = worker.ReceiveEntireAgentGroupsTask(wazuh_common=get_worker_handler(event_loop),
                                                                        logger=logging.getLogger("wazuh"),
                                                                        task_id="0101")
        while not receive_agent_groups_task.task.done():
            await asyncio.sleep(0.01)
        recv_agent_mock.assert_awaited_once()
        assert receive_agent_groups_task.wazuh_common.sync_agent_groups_free is True


@pytest.mark.asyncio
async def test_rit_set_up_coro(event_loop):
    """Check if a callable is being returned by this method."""

    with patch('wazuh.core.cluster.worker.WorkerHandler.process_files_from_master',
               return_value='') as process_files_mock:
        receive_task = worker.ReceiveIntegrityTask(wazuh_common=get_worker_handler(event_loop), logger=None)
        receive_task.wazuh_common = cluster_common.WazuhCommon()
        while not receive_task.task.done():
            await asyncio.sleep(0.01)

        assert receive_task.coro == process_files_mock


@pytest.mark.asyncio
async def test_rit_done_callback(event_loop):
    """Check if a callable is being returned by this method."""

    async def coro(task_id: str, data: str):
        return ''

    def return_coro():
        return coro

    with patch('wazuh.core.cluster.worker.ReceiveIntegrityTask.set_up_coro', side_effect=return_coro):
        receive_task = worker.ReceiveIntegrityTask(wazuh_common=get_worker_handler(event_loop), logger=None)
        receive_task.wazuh_common = cluster_common.WazuhCommon()

        while not receive_task.task.done():
            await asyncio.sleep(0.01)

        assert receive_task.wazuh_common.check_integrity_free is True


# Test SyncWazuhdb class
@pytest.mark.asyncio
async def test_sync_wazuh_db_init(event_loop):
    """Test the '__init__' method from the SyncWazuhdb class."""
    sync_wazuh_db = get_sync_wazuh_db(get_worker_handler(event_loop))
    assert sync_wazuh_db.get_data_command == "get_command"
    assert sync_wazuh_db.set_data_command == "set_command"
    assert sync_wazuh_db.data_retriever is None


@pytest.mark.asyncio
@freeze_time('1970-01-01')
@patch("json.dumps", return_value="")
@patch('wazuh.core.cluster.worker.cluster.run_in_pool', return_value=True)
async def test_sync_wazuh_db_sync_ok(run_in_pool_mock, json_dumps_mock, event_loop):
    """Check if the information is being properly sent to the master node."""
    chunks = True

    def callable_mock(data):
        """Mock method in order to obtain a particular output."""
        if chunks:
            return [data]
        else:
            return []

    sync_wazuh_db = get_sync_wazuh_db(get_worker_handler(event_loop))
    sync_wazuh_db.data_retriever = callable_mock

    # Test try and if
    with patch.object(logging.getLogger("wazuh"), "debug") as logger_debug_mock:
        with patch("wazuh.core.cluster.worker.WorkerHandler.send_string", return_value=b"OK") as send_string_mock:
            with patch("wazuh.core.cluster.worker.WorkerHandler.send_request") as send_request_mock:
                assert await sync_wazuh_db.sync(start_time=10, chunks=["get_command"]) is True
                send_request_mock.assert_called_once_with(command=b"cmd", data=b"OK")
                json_dumps_mock.assert_called_with({"set_data_command": "set_command", "payload": {},
                                                    "chunks": ["get_command"]})
                logger_debug_mock.assert_has_calls([call("Sending chunks.")])

            send_string_mock.assert_called_with(b"")

    # Test else
    chunks = False
    with patch.object(logging.getLogger("wazuh"), "info") as logger_info_mock:
        assert await sync_wazuh_db.sync(start_time=10, chunks=[]) is True
        logger_info_mock.assert_called_once_with("Finished in -10.000s. Updated 0 chunks.")


@pytest.mark.asyncio
@freeze_time('1970-01-01')
@patch("json.dumps", return_value="")
@patch("wazuh.core.cluster.worker.WorkerHandler.send_string", return_value=b"Error")
async def test_sync_wazuh_db_sync_ko(send_string_mock, json_dumps_mock, event_loop):
    """Test if the proper exceptions are raised when needed."""

    def callable_mock(data):
        """Mock method in order to obtain a particular output."""
        return [data]

    sync_wazuh_db = get_sync_wazuh_db(get_worker_handler(event_loop))
    sync_wazuh_db.data_retriever = callable_mock

    # Test try and if
    with pytest.raises(exception.WazuhClusterError, match=r".* 3016 .*"):
        await sync_wazuh_db.sync(start_time=10, chunks=["get_command"])
    json_dumps_mock.assert_called_with({"set_data_command": "set_command", "payload": {}, "chunks": ["get_command"]})
    send_string_mock.assert_called_with(b"")


# Test WorkerHandler class methods.
@pytest.mark.asyncio
async def test_worker_handler_init(event_loop):
    """Test '__init__' method from WorkerHandler class."""

    worker_handler = get_worker_handler(event_loop)
    worker_handler.logger = None
    assert worker_handler.client_data == "Testing Testing master 4.0.0".encode()
    assert "Agent-info sync" in worker_handler.task_loggers
    assert isinstance(worker_handler.task_loggers["Agent-info sync"], logging.Logger)
    assert "Integrity check" in worker_handler.task_loggers
    assert isinstance(worker_handler.task_loggers["Integrity check"], logging.Logger)
    assert "Integrity sync" in worker_handler.task_loggers
    assert isinstance(worker_handler.task_loggers["Integrity sync"], logging.Logger)
    assert worker_handler.agent_info_sync_status == {'date_start': 0.0}
    assert worker_handler.integrity_check_status == {'date_start': 0.0}
    assert worker_handler.integrity_sync_status == {'date_start': 0.0}


@pytest.mark.asyncio
@patch("os.path.exists", return_value=False)
@patch("wazuh.core.utils.mkdir_with_mode")
@patch("os.path.join", return_value="/some/path")
@patch("wazuh.core.cluster.worker.client.AbstractClient.connection_result")
async def test_worker_handler_connection_result(connection_result_mock, join_mock, mkdir_with_mode_mock, exists_mock,
                                                event_loop):
    """Check if the function is called whenever the master sends a response to the worker's hello command."""

    worker_handler = get_worker_handler(event_loop)
    worker_handler.connected = True
    worker_handler.connection_result("something")
    join_mock.assert_called_once_with(core_common.WAZUH_PATH, "queue", "cluster", "Testing")
    exists_mock.assert_called_once_with("/some/path")
    mkdir_with_mode_mock.assert_called_once_with("/some/path")
    connection_result_mock.assert_called_once()


@pytest.mark.asyncio
@patch.object(logging.getLogger("wazuh"), "debug")
async def test_worker_handler_process_request_ok(logger_mock, event_loop):
    """Check if all the command that a worker can receive are being defined."""
    worker_handler = get_worker_handler(event_loop)
    worker_handler.logger = logging.getLogger("wazuh")

    class ClientsMock:
        """Auxiliary class."""

        async def send_request(self, command, error_msg):
            pass

    class LocalServerDapiMock:
        """Auxiliary class."""

        def __init__(self):
            self.clients = {"data": ClientsMock()}

        def add_request(self, data):
            pass

    class ManagerMock:
        """Auxiliary class."""

        def __init__(self):
            self.local_server = LocalServerDapiMock()
            self.dapi = LocalServerDapiMock()

    # Test the first condition
    with patch("wazuh.core.cluster.worker.WorkerHandler.sync_integrity_ok_from_master",
               return_value=b"ok") as ok_mock:
        assert worker_handler.process_request(command=b"syn_m_c_ok", data=b"data") == b"ok"
        ok_mock.assert_called_once()
        logger_mock.assert_called_with("Command received: 'b'syn_m_c_ok''")
    # Test the second condition
    with patch("wazuh.core.cluster.worker.WorkerHandler.setup_receive_files_from_master",
               return_value=b"ok") as setup_mock:
        assert worker_handler.process_request(command=b"syn_m_c", data=b"data") == b"ok"
        setup_mock.assert_called_once()
        logger_mock.assert_called_with("Command received: 'b'syn_m_c''")
    # Test the third condition
    with patch("wazuh.core.cluster.worker.WorkerHandler.end_receiving_integrity",
               return_value=b"ok") as integrity_mock:
        assert worker_handler.process_request(command=b"syn_m_c_e", data=b"data") == b"ok"
        integrity_mock.assert_called_once_with(b"data".decode())
        logger_mock.assert_called_with("Command received: 'b'syn_m_c_e''")
    # Test the fourth condition
    with patch("wazuh.core.cluster.worker.WorkerHandler.error_receiving_integrity",
               return_value=b"ok") as error_integrity_mock:
        assert worker_handler.process_request(command=b"syn_m_c_r", data=b"data") == b"ok"
        error_integrity_mock.assert_called_once_with(b"data".decode())
        logger_mock.assert_called_with("Command received: 'b'syn_m_c_r''")
    # Test the fifth condition
    with patch("wazuh.core.cluster.worker.WorkerHandler.setup_sync_integrity",
               return_value=b"ok") as setup_sync_integrity_mock:
        assert worker_handler.process_request(command=b"syn_g_m_w", data=b"data") == b"ok"
        setup_sync_integrity_mock.assert_called_once_with(b"syn_g_m_w", b"data")
        logger_mock.assert_called_with("Command received: 'b'syn_g_m_w''")
    # Test the sixth condition
    with patch("wazuh.core.cluster.master.Master.setup_task_logger",
               worker_handler.setup_task_logger('Agent-info sync')) as setup_task_logger_mock:
        with patch("wazuh.core.cluster.worker.c_common.end_sending_agent_information",
                   return_value=b"ok") as sync_mock:
            assert worker_handler.process_request(
                command=b"syn_m_a_e", data=b'{"updated_chunks": 4, "error_messages": []}') == b"ok"
            sync_mock.assert_called_once_with(setup_task_logger_mock,
                                              datetime.datetime(1970, 1, 1, 0, 0),
                                              b'{"updated_chunks": 4, "error_messages": []}'.decode())
            logger_mock.assert_called_with("Command received: 'b'syn_m_a_e''")
    # Test the seventh condition
    with patch("wazuh.core.cluster.worker.c_common.error_receiving_agent_information",
               return_value=b"ok") as error_mock:
        assert worker_handler.process_request(command=b"syn_m_a_err", data=b"data") == b"ok"
        error_mock.assert_called_once_with(
            worker_handler.task_loggers['Agent-info sync'], b"data".decode(), info_type='agent-info')
        logger_mock.assert_called_with("Command received: 'b'syn_m_a_err''")
    # Test the eighth condition
    with patch("wazuh.core.cluster.worker.WorkerHandler.forward_dapi_response",
               side_effect=b"ok") as forward_dapi_mock:
        assert worker_handler.process_request(command=b"dapi_res",
                                              data=b"data") == (b'ok', b'Response forwarded to worker')
        while not forward_dapi_mock.await_count:
            await asyncio.sleep(0.01)
        forward_dapi_mock.assert_called_with(b"data")
        logger_mock.assert_called_with("Command received: 'b'dapi_res''")
    # Test the ninth condition
    with patch("wazuh.core.cluster.worker.WorkerHandler.forward_sendsync_response",
               return_value=b"ok") as forward_sendsync_mock:
        assert worker_handler.process_request(command=b"sendsyn_res",
                                              data=b"data") == (b'ok', b'Response forwarded to worker')
        while not forward_sendsync_mock.await_count:
            await asyncio.sleep(0.01)
        forward_sendsync_mock.assert_called_once_with(b"data")
        logger_mock.assert_called_with("Command received: 'b'sendsyn_res''")
    # Test the tenth condition
    worker_handler.server = ManagerMock()
    with patch.object(ClientsMock, "send_request") as send_request_mock:
        assert worker_handler.process_request(command=b"dapi_err",
                                              data=b"data 2") == (b'ok', b'DAPI error forwarded to worker')
        while not send_request_mock.await_count:
            await asyncio.sleep(0.01)
        send_request_mock.assert_called_once_with(b"dapi_err", b"2")
        logger_mock.assert_called_with("Command received: 'b'dapi_err''")
    # Test the eleventh condition
    with patch.object(ClientsMock, "send_request") as send_request_mock:
        assert worker_handler.process_request(command=b"sendsyn_err",
                                              data=b"data 2") == (b'ok', b'SendSync error forwarded to worker')
        while not send_request_mock.await_count:
            await asyncio.sleep(0.01)
        send_request_mock.assert_called_once_with(b"err", b"2")
        logger_mock.assert_called_with("Command received: 'b'sendsyn_err''")
    # Test the twelfth condition
    with patch.object(LocalServerDapiMock, "add_request") as add_request_mock:
        assert worker_handler.process_request(command=b"dapi",
                                              data=b"data") == (b'ok', b'Added request to API requests queue')
        add_request_mock.assert_called_once_with(b"master*data")
        logger_mock.assert_called_with("Command received: 'b'dapi''")
    # Test the thirteenth condition
    with patch("wazuh.core.cluster.worker.client.AbstractClient.process_request",
               return_value=True) as process_request_mock:
        assert worker_handler.process_request(command=b"random", data=b"data") is True
        process_request_mock.assert_called_once_with(b"random", b"data")


@pytest.mark.asyncio
@patch.object(logging.getLogger("wazuh"), "info")
@patch("wazuh.core.cluster.worker.client.AbstractClient.connection_lost")
@patch("wazuh.core.cluster.worker.cluster.clean_up")
async def test_worker_handler_connection_lost(clean_up_mock, connection_lost_mock, logger_mock, event_loop):
    """Check if all the pending tasks are closed when the connection between workers and master is lost."""

    worker_handler = get_worker_handler(event_loop)
    worker_handler.logger = logging.getLogger("wazuh")

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

    worker_handler.sync_tasks = {"key": PendingTaskMock()}
    worker_handler.connection_lost(Exception())

    connection_lost_mock.assert_called_once()
    clean_up_mock.assert_called_once_with(node_name=worker_handler.name)


@pytest.mark.asyncio
@patch.object(logging.getLogger("wazuh"), "debug")
async def test_worker_handler_process_request_ko(logger_mock, event_loop):
    """Test the correct exception raise at method 'process_request'."""

    class ClientsMock:
        """Auxiliary class."""

        def send_request(self, command, error_msg):
            raise exception.WazuhClusterError(1001)

    class LocalServerDapiMock:
        """Auxiliary class."""

        def __init__(self):
            self.clients = {"data": ClientsMock()}

        def add_request(self, data):
            pass

    class ManagerMock:
        """Auxiliary class."""

        def __init__(self):
            self.local_server = LocalServerDapiMock()
            self.dapi = LocalServerDapiMock()

    worker_handler = get_worker_handler(event_loop)
    worker_handler.server = ManagerMock()
    with pytest.raises(exception.WazuhClusterError, match=r".* 1001 .*"):
        with patch.object(worker_handler, 'log_exceptions', return_value='') as log_exceptions_mock:
            worker_handler.process_request(command=b"sendsyn_err", data=b"data 1")
    logger_mock.assert_called_with("Command received: 'b'sendsyn_err''")


@pytest.mark.asyncio
async def test_worker_handler_get_manager(event_loop):
    """Check if the Worker object is being properly returned."""

    assert isinstance(get_worker_handler(event_loop).get_manager(), client.AbstractClientManager)


@pytest.mark.asyncio
@patch("wazuh.core.cluster.common.WazuhCommon.setup_receive_file", return_value=b"ok")
async def test_master_handler_setup_sync_integrity(setup_receive_file_mock, event_loop):
    """Check if the synchronization process was correctly started."""

    worker_handler = get_worker_handler(event_loop)

    # Test the first condition
    assert worker_handler.setup_sync_integrity(b'syn_g_m_w', b"data") == b"ok"

    # Test the else condition
    assert worker_handler.setup_sync_integrity(b'unknown', b"data") == b"ok"

    setup_receive_file_mock.has_calls([call(worker.ReceiveAgentGroupsTask, b"ok"), call(None, b"ok")])


@pytest.mark.asyncio
@freeze_time('1970-01-01')
@patch.object(logging.getLogger("wazuh.Integrity check"), "info")
@patch("wazuh.core.cluster.common.WazuhCommon.setup_receive_file", return_value="OK")
async def test_worker_handler_setup_receive_files_from_master(setup_receive_file_mock, logger_mock, event_loop):
    """Check is a task was set up to wait until the integrity information has been received from the master and
    processed."""
    worker_handler = get_worker_handler(event_loop)
    worker_handler.integrity_check_status = {"date_start": 0}
    assert worker_handler.setup_receive_files_from_master() == "OK"
    logger_mock.assert_called_once_with("Finished in 0.000s. Sync required.")
    setup_receive_file_mock.assert_called_once()


@pytest.mark.asyncio
@patch("wazuh.core.cluster.common.WazuhCommon.end_receiving_file", return_value=(b"OK", b"OK"))
async def test_worker_handler_end_receiving_integrity(end_receiving_file_mock, event_loop):
    """Test if a task was notified about some information reception."""

    worker_handler = get_worker_handler(event_loop)
    assert worker_handler.end_receiving_integrity("file_name") == (b"OK", b"OK")
    end_receiving_file_mock.assert_called_once_with(task_and_file_names="file_name", logger_tag="Integrity sync")


@pytest.mark.asyncio
@patch("wazuh.core.cluster.common.WazuhCommon.error_receiving_file", return_value=(b"error", b"error"))
async def test_worker_handler_error_receiving_integrity(error_receiving_file_mock, event_loop):
    """Check if a task was notified about some error that had place during the process."""

    worker_handler = get_worker_handler(event_loop)
    assert worker_handler.error_receiving_integrity("file_name_and_errors") == (b"error", b"error")
    error_receiving_file_mock.assert_called_once_with(task_id_and_error_details="file_name_and_errors",
                                                      logger_tag="Integrity sync")


# @pytest.mark.asyncio
# @freeze_time('1970-01-01')
# @patch.object(logging.getLogger("wazuh.Integrity check"), "info")
# async def test_worker_handler_sync_integrity_ok_from_master(logger_mock, event_loop):
#     """Check the correct output message when a command 'sync_m_c_ok' takes place."""

#     worker_handler = get_worker_handler(event_loop)
#     worker_handler.integrity_check_status = {"date_start": 0}
#     assert worker_handler.sync_integrity_ok_from_master() == (b'ok', b'Thanks')
#     logger_mock.assert_called_once_with("Finished in 0.000s. Sync not required.")


@pytest.mark.asyncio
@patch("wazuh.core.wdb.socket.socket")
async def test_worker_compare_agent_groups_checksums(socket_mock, event_loop):
    """Check all the possible cases in the checksums comparison."""

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._debug = []
            self._debug2 = []

        def debug(self, debug):
            self._debug.append(debug)

        def debug2(self, debug2):
            self._debug2.append(debug2)

    logger = LoggerMock()
    wdb_conn = AsyncWazuhDBConnection()
    w_handler = get_worker_handler(event_loop)
    w_handler.connected = True
    sync_object = cluster_common.SyncWazuhdb(manager=w_handler, logger=logger, cmd=b'syn_g_m_w',
                                             data_retriever=wdb_conn.run_wdb_command,
                                             get_data_command='global sync-agent-groups-get ',
                                             get_payload={"condition": "sync_status", "get_global_hash": True})

    with patch('wazuh.core.cluster.worker.c_common.SyncWazuhdb', return_value=sync_object):
        # Nothing is returned
        with patch.object(sync_object, 'retrieve_information', side_effect=[None]):
            assert await w_handler.compare_agent_groups_checksums(master_checksum='CKS', logger=logger) == False

        # The checksums are equal
        with patch.object(sync_object, 'retrieve_information', side_effect=[['[{"data": "", "hash": "CKS"}]']]):
            assert await w_handler.compare_agent_groups_checksums(master_checksum='CKS', logger=logger) == True

        # The checksums are different.
        with patch.object(sync_object, 'retrieve_information', side_effect=[['[{"data": "", "hash": "!CKS"}]']]):
            assert await w_handler.compare_agent_groups_checksums(master_checksum='CKS', logger=logger) == False
            assert 'The checksum of master (CKS) and worker (!CKS) are different.' in logger._debug

        # The hash is not returned.
        with patch.object(sync_object, 'retrieve_information', side_effect=[['[{"data": ""}]']]):
            assert await w_handler.compare_agent_groups_checksums(master_checksum='CKS', logger=logger) == False
            assert "The checksum of master (CKS) and worker (UNABLE TO COLLECT FROM DB) " \
                   "are different." in logger._debug


@pytest.mark.asyncio
@patch('wazuh.core.cluster.worker.c_common.Handler.send_request')
async def test_worker_check_agent_groups_checksums(send_request_mock, event_loop):
    """Check that the function check_agent_groups_checksums correctly checks the comparison counter."""

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._debug = []
            self._info = []

        def debug(self, debug):
            self._debug.append(debug)

        def info(self, info):
            self._info.append(info)

        def clear(self):
            self._info.clear()
            self._debug.clear()

    logger = LoggerMock()
    worker_handler = get_worker_handler(event_loop)
    worker_handler.agent_groups_mismatch_counter = 0
    data = {"chunks": ['[{"hash": "a"}]']}

    with patch('wazuh.core.cluster.worker.WorkerHandler.compare_agent_groups_checksums', return_value=False):
        # Check that when the checksums are different the counter is incremented
        await worker_handler.check_agent_groups_checksums(data=data, logger=logger)
        assert worker_handler.agent_groups_mismatch_counter == 1
        assert 'Checksum comparison failed (1/5).' in logger._debug
        assert len(logger._info) == 0

        # Check that when the counter exceeds the maximum limit, the number of attempts is not printed in the logger
        logger.clear()
        worker_handler.agent_groups_mismatch_counter = worker_handler.agent_groups_mismatch_limit
        await worker_handler.check_agent_groups_checksums(data=data, logger=logger)
        assert worker_handler.agent_groups_mismatch_counter == 0
        send_request_mock.assert_called_once_with(command=b'syn_w_g_c', data=b'')
        assert 'Sent request to obtain all agent-groups information from the master node.' in logger._info

    with patch('wazuh.core.cluster.worker.WorkerHandler.compare_agent_groups_checksums', return_value=True):
        # Check that when the checksums are equal, the counter is reset (without previous attempts).
        logger.clear()
        worker_handler.agent_groups_mismatch_counter = 0
        await worker_handler.check_agent_groups_checksums(data=data, logger=logger)
        assert worker_handler.agent_groups_mismatch_counter == 0
        assert 'The checksum of both databases match. ' in logger._debug

        # Check that when the checksum are equal the counter is reset (with previous attempts).
        logger.clear()
        worker_handler.agent_groups_mismatch_counter = 1
        await worker_handler.check_agent_groups_checksums(data=data, logger=logger)
        assert worker_handler.agent_groups_mismatch_counter == 0
        assert 'The checksum of both databases match. Counter reset.' in logger._debug


@pytest.mark.asyncio
@freeze_time('1970-01-01')
@patch("wazuh.core.cluster.worker.WorkerHandler.recalculate_group_hash", return_value=AsyncMock())
@patch('wazuh.core.cluster.worker.WorkerHandler.check_agent_groups_checksums', return_value='')
@patch('wazuh.core.cluster.common.Handler.send_request', return_value='check')
@patch('wazuh.core.cluster.common.Handler.update_chunks_wdb', return_value={'updated_chunks': 1})
@patch('wazuh.core.cluster.common.Handler.get_chunks_in_task_id', return_value='chunks')
async def test_worker_handler_recv_agent_groups_information(get_chunks_in_task_id_mock, update_chunks_wdb_mock,
                                                            send_request_mock, check_agent_groups_checksums_mock,
                                                            recalculate_group_hash_mock, event_loop):
    """Check that the wazuh-db data reception task is created."""

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._info = []

        def info(self, info):
            self._info.append(info)

    def reset_mock():
        list(map(lambda x: x.reset_mock(), [get_chunks_in_task_id_mock, update_chunks_wdb_mock,
                                            send_request_mock, check_agent_groups_checksums_mock]))

    logger = LoggerMock()
    logger_c = LoggerMock()
    worker_handler = get_worker_handler(event_loop)
    worker_handler.task_loggers['Agent-groups recv'] = logger
    worker_handler.task_loggers['Agent-groups recv full'] = logger_c

    assert await worker_handler.recv_agent_groups_periodic_information(task_id=b'17',
                                                                       info_type='agent-groups') == 'check'
    get_chunks_in_task_id_mock.assert_called_once_with(b'17', b'syn_w_g_err')
    update_chunks_wdb_mock.assert_called_once_with('chunks', 'agent-groups', logger, b'syn_w_g_err', 0)
    send_request_mock.assert_called_once_with(command=b'syn_w_g_e', data=b'{"updated_chunks": 1}')
    check_agent_groups_checksums_mock.assert_called_once_with('chunks', logger)
    assert 'Starting.' in logger._info
    assert 'Finished in 0.000s. Updated 1 chunks.' in logger._info
    reset_mock()

    assert await worker_handler.recv_agent_groups_entire_information(task_id=b'17', info_type='agent-groups') == 'check'
    get_chunks_in_task_id_mock.assert_called_once_with(b'17', b'syn_wgc_err')
    update_chunks_wdb_mock.assert_called_once_with('chunks', 'agent-groups', logger_c, b'syn_wgc_err', 0)
    send_request_mock.assert_called_once_with(command=b'syn_wgc_e', data=b'{"updated_chunks": 1}')
    check_agent_groups_checksums_mock.assert_called_once_with('chunks', logger_c)
    assert 'Starting.' in logger_c._info
    assert 'Finished in 0.000s. Updated 1 chunks.' in logger_c._info


@freeze_time('1970-01-01')
@pytest.mark.asyncio
@patch.object(wazuh.core.cluster.worker.json, "dumps", return_value="")
@patch.object(logging.getLogger("wazuh.Integrity check"), "info")
@patch.object(logging.getLogger("wazuh.Integrity check"), "error")
@patch("wazuh.core.cluster.common.SyncFiles.sync", return_value=True)
@patch("wazuh.core.cluster.cluster.get_files_status", return_value={})
@patch("wazuh.core.cluster.worker.client.common.Handler.send_request")
@patch("wazuh.core.cluster.common.SyncTask.request_permission", return_value=True)
async def test_worker_handler_sync_integrity(request_permission_mock,
                                             send_request_mock,
                                             get_files_status,
                                             sync_mock,
                                             error_mock,
                                             logger_info_mock,
                                             json_dumps_mock,
                                             event_loop):
    """Check if files status are correctly obtained and sent to the master."""

    class ManagerMock:
        """Auxiliary class."""

        def __init__(self):
            self.task_pool = None
            self.integrity_control = {}

    async def cluster_run_in_pool_mock(loop, pool, f, *args, **kwargs):
        partial(f, *args, **kwargs)()
        return {'path': 'test'}, {}

    worker_handler = get_worker_handler(event_loop)
    worker_handler.check_integrity_free = True
    worker_handler.connected = True
    worker_handler.server = ManagerMock()

    # Test the try
    with (patch('wazuh.core.cluster.worker.cluster.run_in_pool', side_effect=cluster_run_in_pool_mock) as
          run_in_pool_mock):
        try:
            await asyncio.wait_for(worker_handler.sync_integrity(), 0.2)
        except asyncio.exceptions.TimeoutError:
            pass

        request_permission_mock.assert_awaited()
        get_files_status.assert_called()
        run_in_pool_mock.assert_awaited()

        sync_mock.assert_awaited_with(files={}, files_metadata={'path': 'test'}, metadata_len=1, task_pool=None)
        logger_info_mock.assert_called_with("Starting.")
        assert worker_handler.integrity_check_status["date_start"] == 0.0

        run_in_pool_mock.side_effect = exception.WazuhException(1001)
        try:
            await asyncio.wait_for(worker_handler.sync_integrity(), 0.2)
        except asyncio.exceptions.TimeoutError:
            pass

        error_mock.assert_called_with(f"Error synchronizing integrity: {exception.WazuhException(1001)}")
        json_dumps_mock.assert_called_with(exception.WazuhException(1001), cls=cluster_common.WazuhJSONEncoder)
        send_request_mock.assert_awaited_with(command=b'syn_i_w_m_r', data=b'None ' + "".encode())

        run_in_pool_mock.side_effect = Exception
        try:
            await asyncio.wait_for(worker_handler.sync_integrity(), 0.2)
        except asyncio.exceptions.TimeoutError:
            pass

        error_mock.assert_called_with("Error synchronizing integrity: ")
        json_dumps_mock.assert_called_with(exception.WazuhClusterError(code=1000, extra_message=str(Exception())),
                                           cls=cluster_common.WazuhJSONEncoder)
        send_request_mock.assert_called_with(command=b'syn_i_w_m_r', data=b'None ' + "".encode())


@pytest.mark.asyncio
@freeze_time('1970-01-01')
@patch('asyncio.sleep', side_effect=Exception())
@patch("wazuh.core.cluster.master.AsyncWazuhDBConnection")
@patch('wazuh.core.cluster.common.SyncWazuhdb')
async def test_worker_handler_sync_agent_info(SyncWazuhdb_mock, AsyncWazuhDBConnection_mock, sleep_mock, event_loop):
    """Check that the agent-info task is properly configured."""

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._info = []

        def info(self, info):
            self._info.append(info)

    logger = LoggerMock()
    w_handler = get_worker_handler(event_loop)
    w_handler.connected = True
    w_handler.task_loggers['Agent-info sync'] = logger
    SyncWazuhdb_mock.return_value.request_permission = AsyncMock()
    retrieve_agents_information_mock = AsyncMock()
    agents_sync = {
        'syncreq': [
            {'id': 1, 'name': 'test'}
        ],
        'syncreq_keepalive': [],
        'syncreq_status': [],
    }
    retrieve_agents_information_mock.return_value = agents_sync
    SyncWazuhdb_mock.return_value.retrieve_agents_information = retrieve_agents_information_mock
    SyncWazuhdb_mock.return_value.sync = AsyncMock()

    try:
        await w_handler.sync_agent_info()
    except Exception:
        pass

    SyncWazuhdb_mock.assert_called_once_with(manager=w_handler, logger=logger, cmd=b'syn_a_w_m', data_retriever=None,
                                             get_data_command='global sync-agent-info-get ',
                                             set_data_command='global sync-agent-info-set')
    SyncWazuhdb_mock.return_value.request_permission.assert_called_once()
    SyncWazuhdb_mock.return_value.retrieve_agents_information.assert_called_once()
    SyncWazuhdb_mock.return_value.sync.assert_called_once_with(start_time=ANY, chunks=agents_sync)
    assert w_handler.agent_info_sync_status == {'date_start': 0.0}
    assert logger._info == ['Starting.']


@pytest.mark.asyncio
@patch('asyncio.sleep', side_effect=Exception())
@patch("wazuh.core.cluster.master.AsyncWazuhDBConnection")
@patch('wazuh.core.cluster.common.SyncWazuhdb')
async def test_worker_handler_sync_agent_info_ko(SyncWazuhdb_mock, AsyncWazuhDBConnection_mock, sleep_mock, event_loop):
    """Check that the agent-info task is properly configured."""

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._error = []

        def error(self, info):
            self._error.append(info)

    logger = LoggerMock()
    w_handler = get_worker_handler(event_loop)
    w_handler.connected = True
    w_handler.task_loggers['Agent-info sync'] = logger

    try:
        await w_handler.sync_agent_info()
    except Exception:
        pass

    assert logger._error == ["Error synchronizing agent info: object MagicMock can't be used in 'await' expression"]


@pytest.mark.asyncio
@freeze_time('1970-01-01')
@patch.object(logging.getLogger("wazuh.Integrity sync"), "debug")
@patch("wazuh.core.cluster.common.SyncFiles.sync", return_value=True)
@patch('wazuh.core.cluster.worker.perf_counter', return_value=0)
@patch("wazuh.core.cluster.cluster.merge_info", return_value=("n_files", "merged_file"))
async def test_worker_handler_sync_extra_valid(merge_info_mock, perf_counter_mock, sync_mock, logger_debug_mock,
                                               event_loop):
    """Test the 'sync_extra_valid' method."""

    class ManagerMock:
        """Auxiliary class."""

        def __init__(self):
            self.task_pool = None

    # Test the try
    extra_valid = {"/missing/path": 0, "missing/path2": 1}
    worker_handler = get_worker_handler(event_loop)
    worker_handler.server = ManagerMock()
    with patch.object(logging.getLogger("wazuh.Integrity sync"), "info") as logger_info_mock:
        await worker_handler.sync_extra_valid(extra_valid)
        logger_debug_mock.assert_has_calls([call("Starting sending extra valid files to master."),
                                            call("Finished sending extra valid files in 0.000s.")])
        logger_info_mock.assert_called_once_with("Finished in 0.000s.")
        merge_info_mock.assert_called_once_with(merge_type='TYPE', node_name="Testing",
                                                files=extra_valid.keys())
        sync_mock.assert_called_once_with(
            files={'merged_file': {'merged': True, 'merge_type': 'TYPE', 'merge_name': 'merged_file',
                                   'cluster_item_key': 'RELATIVE_PATH'}},
            files_metadata={"merged_file": {'merged': True, 'merge_type': 'TYPE', 'merge_name': 'merged_file',
                                            'cluster_item_key': 'RELATIVE_PATH'}},
            metadata_len=1, task_pool=None)

    # Test the first exception
    with patch("wazuh.core.cluster.worker.WorkerHandler.send_request") as send_request_mock:
        with patch.object(logging.getLogger("wazuh.Integrity sync"), "error") as logger_error_mock:
            merge_info_mock.side_effect = exception.WazuhException(1001)
            cls = cluster_common.WazuhJSONEncoder
            await worker_handler.sync_extra_valid(extra_valid)
            logger_debug_mock.assert_called_with("Starting sending extra valid files to master.")
            logger_error_mock.assert_called_once_with(
                f"Error synchronizing extra valid files: {exception.WazuhException(1001)}")
            send_request_mock.assert_called_once_with(command=b'syn_i_w_m_r',
                                                      data=b'None ' + json.dumps(exception.WazuhException(1001),
                                                                                 cls=cls).encode())
            # Test second exception
            with patch("json.dumps", return_value="data_to_encode"):
                merge_info_mock.side_effect = Exception()
                await worker_handler.sync_extra_valid(extra_valid)
                logger_debug_mock.assert_called_with("Starting sending extra valid files to master.")
                logger_error_mock.assert_called_with("Error synchronizing extra valid files: ")
                send_request_mock.assert_called_with(command=b'syn_i_w_m_r',
                                                     data=b'None ' + "data_to_encode".encode())


@pytest.mark.asyncio
@freeze_time('1970-01-01')
@patch("shutil.rmtree")
@patch("json.dumps", return_value="")
@patch("wazuh.core.cluster.cluster.decompress_files")
@patch.object(logging.getLogger("wazuh.Integrity sync"), "info")
@patch.object(logging.getLogger("wazuh.Integrity sync"), "debug")
@patch("wazuh.core.cluster.worker.client.common.Handler.send_request")
@patch("wazuh.core.cluster.worker.WorkerHandler.update_master_files_in_worker")
async def test_worker_handler_process_files_from_master_ok(update_files_mock, send_request_mock, logger_debug_mock,
                                                           logger_info_mock, decompress_files_mock,
                                                           json_dumps_mock,
                                                           rmtree_mock, event_loop):
    """Test if relevant actions are being performed for a file according to its status."""

    async def unlock_event(event: asyncio.Event):
        event.set()

    def cluster_run_in_pool_mock(loop, pool, f, *args, **kwargs):
        partial(f, *args, **kwargs)()
        return ko_files_ret, zip_path

    class TaskMock:
        """Auxiliary class."""

        def __init__(self):
            self.filename = "path of the zip"

    class ManagerMock:
        """Auxiliary class."""

        def __init__(self):
            self.task_pool = None
            self.integrity_control = {}

    ko_files = [{"shared": "shared_files", "TYPE": "extra_valid_files", "missing": "missing_files",
                 "extra": "extra files"},
                {"shared": "shared_files", "extra_valid": "", "missing": "missing_files",
                 "extra": "extra files"}]
    zip_path = "/zip/path"

    all_mocks = [update_files_mock, send_request_mock, logger_debug_mock, logger_info_mock, decompress_files_mock,
                 json_dumps_mock,
                 rmtree_mock]

    # Test try and nested if
    worker_handler = get_worker_handler(event_loop)
    worker_handler.sync_tasks["task_id"] = TaskMock()
    worker_handler.server = ManagerMock()
    decompress_files_mock.return_value = (ko_files[0], zip_path)
    event = asyncio.Event()

    with patch('wazuh.core.cluster.cluster.run_in_pool', side_effect=cluster_run_in_pool_mock) as run_in_pool_mock:
        ko_files_ret = ko_files[0]
        await asyncio.gather(worker_handler.process_files_from_master(name="task_id", file_received=event),
                             unlock_event(event))
        update_files_mock.assert_called_once_with(ko_files[0], zip_path, cluster_items)
        send_request_mock.assert_not_called()
        logger_debug_mock.assert_has_calls(
            [call("Worker does not meet integrity checks. Actions required."), call("Updating local files: Start."),
             call("Updating local files: End.")])
        logger_info_mock.assert_has_calls(
            [call("Starting."),
             call("Files to create: 13 | Files to update: 12 | Files to delete: 11")])
        assert run_in_pool_mock.call_count == 2
        decompress_files_mock.assert_called_once_with("path of the zip")
        json_dumps_mock.assert_not_called()
        rmtree_mock.assert_called_once_with(zip_path)

        # Reset all mocks
        for mock in all_mocks:
            mock.reset_mock()

        # Test try and nested else
        worker_handler.sync_tasks["task_id"] = TaskMock()
        ko_files_ret = ko_files[1]
        decompress_files_mock.return_value = (ko_files[1], zip_path)
        event = asyncio.Event()
        await asyncio.gather(worker_handler.process_files_from_master(name="task_id", file_received=event),
                             unlock_event(event=event))

        update_files_mock.assert_called_once_with(ko_files[1], zip_path, cluster_items)
        send_request_mock.assert_not_called()
        logger_debug_mock.assert_has_calls(
            [call("Worker does not meet integrity checks. Actions required."), call("Updating local files: Start."),
             call("Updating local files: End.")])
        logger_info_mock.assert_has_calls([
            call("Starting."), call("Files to create: 13 | Files to update: 12 | Files to delete: 11")])
        decompress_files_mock.assert_called_once_with("path of the zip")
        json_dumps_mock.assert_not_called()
        rmtree_mock.assert_called_once_with(zip_path)

        # Reset all mocks
        for mock in all_mocks:
            mock.reset_mock()

        # Test first except
        worker_handler.sync_tasks["task_id"] = TaskMock()
        decompress_files_mock.side_effect = exception.WazuhException(1001)
        event = asyncio.Event()
        await asyncio.gather(worker_handler.process_files_from_master(name="task_id", file_received=event),
                             unlock_event(event))

        update_files_mock.assert_not_called()
        send_request_mock.assert_called_once_with(command=b'syn_i_w_m_r', data=b'None ')
        logger_debug_mock.assert_not_called()
        logger_info_mock.assert_called_once_with("Starting.")
        json_dumps_mock.assert_called_once_with(exception.WazuhException(1001), cls=cluster_common.WazuhJSONEncoder)
        rmtree_mock.assert_not_called()

        # Reset all mocks
        for mock in all_mocks:
            mock.reset_mock()

        # Test second except
        worker_handler.sync_tasks["task_id"] = TaskMock()
        decompress_files_mock.side_effect = Exception()
        event = asyncio.Event()
        await asyncio.gather(worker_handler.process_files_from_master(name="task_id", file_received=event),
                             unlock_event(event))

        update_files_mock.assert_not_called()
        send_request_mock.assert_called_once_with(command=b'syn_i_w_m_r', data=b'None ')
        logger_debug_mock.assert_not_called()
        logger_info_mock.assert_called_once_with("Starting.")
        json_dumps_mock.assert_called_once_with(exception.WazuhClusterError(code=1000, extra_message=str(Exception())),
                                                cls=cluster_common.WazuhJSONEncoder)
        rmtree_mock.assert_not_called()


@pytest.mark.asyncio
@patch("json.dumps", return_value="")
@patch("wazuh.core.cluster.worker.client.common.Handler.send_request")
async def test_worker_handler_process_files_from_master_ko(send_request_mock,
                                                           json_dumps_mock,
                                                           event_loop):
    """Test if all the exceptions are being properly handled."""

    async def unlock_event(event: asyncio.Event):
        event.set()

    class TaskMock:
        """Auxiliary class."""

        def __init__(self):
            self.filename = Exception()

    def raise_exception():
        raise Exception()

    worker_handler = get_worker_handler(event_loop)
    event = asyncio.Event()
    with pytest.raises(Exception):
        worker_handler.sync_tasks["task_id"] = TaskMock()
        await asyncio.gather(worker_handler.process_files_from_master(name="task_id", file_received=event),
                             unlock_event(event))
    json_dumps_mock.assert_called_with(exception.WazuhClusterError(code=1000, extra_message=str(Exception())),
                                       cls=cluster_common.WazuhJSONEncoder)
    send_request_mock.assert_called_with(command=b'syn_i_w_m_r', data=b'None ')

    worker_handler.cluster_items['intervals']['communication']['timeout_receiving_file'] = 0.1
    event = asyncio.Event()
    with pytest.raises(exception.WazuhClusterError, match=r".* 3039 .*"):
        await asyncio.gather(worker_handler.process_files_from_master(name="task_id", file_received=event))
    send_request_mock.assert_called_with(command=b'cancel_task', data=b'task_id ')

    event = asyncio.Event()
    with pytest.raises(exception.WazuhClusterError, match=r".* 3040 .*"):
        with patch.object(event, 'wait', side_effect=raise_exception):
            await asyncio.gather(worker_handler.process_files_from_master(name="task_id", file_received=event))
    send_request_mock.assert_called_with(command=b'cancel_task', data=b'task_id ')


@pytest.mark.asyncio
@patch("builtins.open")
@patch("os.path.exists", return_value=False)
@patch("wazuh.core.cluster.worker.safe_move")
@patch("wazuh.core.cluster.worker.utils.mkdir_with_mode")
@patch("os.path.join", return_value="queue/testing/")
@patch("wazuh.core.common.wazuh_uid", return_value="wazuh_uid")
@patch("wazuh.core.common.wazuh_gid", return_value="wazuh_gid")
@patch('wazuh.core.analysis.is_ruleset_file', return_value=False)
@patch('wazuh.core.analysis.send_reload_ruleset_msg', return_value=RulesetReloadResponse({'error': 0}))
async def test_worker_handler_update_master_files_in_worker_ok(mock_reload, mock_is_ruleset, wazuh_gid_mock, wazuh_uid_mock, path_join_mock,
                                                               mkdir_with_mode_mock, safe_move_mock, path_exists_mock,
                                                               open_mock, event_loop):
    """Check if the method is properly receiving and updating files."""

    all_mocks = [wazuh_gid_mock, wazuh_uid_mock, path_join_mock, mkdir_with_mode_mock, safe_move_mock, open_mock,
                 path_exists_mock]

    worker_handler = get_worker_handler(event_loop)

    # As the method has two large for, we will make the condition for the first one equal to something empty
    worker_handler.cluster_items["files"]["cluster_item_key"]["remove_subdirs_if_empty"] = {}

    # Test the first for: for -> if -> for -> try
    # In the nested method, with the first value sent to the 'update_master_files_in_worker' (shared), we
    # are testing the if, meanwhile with the second (missing), we are testing the else.
    with patch("wazuh.core.cluster.cluster.unmerge_info", return_value=[("name", "content", "_")]):
        with patch("os.remove") as os_remove_mock:
            result_logs = worker_handler.update_master_files_in_worker(
                ko_files={"shared": {
                    "filename1": {"merged": "value", "cluster_item_key": "cluster_item_key"}},
                    "missing": {
                        "filename1": {"merged": None, "cluster_item_key": "cluster_item_key"}},
                    "extra": {"filename3": {"cluster_item_key": "cluster_item_key"}}}, zip_path="/zip/path",
                cluster_items=cluster_items)

            os_remove_mock.assert_any_call("queue/testing/")
            assert result_logs['error'] == defaultdict(list)
            assert result_logs['debug2'] == {"filename1": ["Processing file filename1", "Processing file filename1"],
                                             "filename3": ["Remove file: 'filename3'"]}
            path_join_mock.assert_has_calls([call(core_common.WAZUH_PATH, 'filename1'),
                                             call(core_common.WAZUH_PATH, 'name'),
                                             call(core_common.WAZUH_PATH, 'filename1'),
                                             call('/zip/path', 'filename1'),
                                             call(core_common.WAZUH_PATH, 'filename3')])
            wazuh_uid_mock.assert_called_with()
            wazuh_gid_mock.assert_called_with()
            mkdir_with_mode_mock.assert_any_call("queue/testing")
            assert safe_move_mock.call_count == 2
            open_mock.assert_called_once()
            path_exists_mock.assert_called_once()

            # Reset all mocks
            for mock in all_mocks:
                mock.reset_mock()

    # Test the first for: for -> if -> for -> except AND for -> elif -> for -> try -> except -> if
    result_logs = worker_handler.update_master_files_in_worker(
        {"shared": {"filename1": "data1"}, "missing": {"filename2": "data2"},
         "extra": {"filename3": {"cluster_item_key": "cluster_item_key"}}}, "/zip/path",
        cluster_items=cluster_items)

    assert result_logs['error'] == {'shared': ["Error processing shared file 'filename1': "
                                               "string indices must be integers"],
                                    'missing': ["Error processing missing file 'filename2': "
                                                "string indices must be integers"]
                                    }

    assert result_logs['debug2'] == {'filename1': ["Processing file filename1"],
                                     'filename3': ["Remove file: 'filename3'",
                                                   "File filename3 doesn't exist."],
                                     'filename2': ["Processing file filename2"]}
    assert result_logs['generic_errors'] == ["Found errors: 1 overwriting, 1 creating and 0 removing"]

    path_join_mock.assert_has_calls([call(core_common.WAZUH_PATH, "filename1"),
                                     call(core_common.WAZUH_PATH, "filename2"),
                                     call(core_common.WAZUH_PATH, "filename3")])
    wazuh_uid_mock.assert_not_called()
    wazuh_gid_mock.assert_not_called()
    mkdir_with_mode_mock.assert_not_called()
    safe_move_mock.assert_not_called()
    open_mock.assert_not_called()
    path_exists_mock.assert_not_called()

    # Reset all mocks
    for mock in all_mocks:
        mock.reset_mock()

    # Test the first for: for -> if -> for -> except AND for -> elif -> for -> try -> except -> else AND
    # for -> elif -> for -> except
    path_join_mock.return_value = "queue/testing_mock/"
    result_logs = worker_handler.update_master_files_in_worker(
        {"shared": {"filename1": "data1"}, "missing": {"filename2": "data2"},
         "extra": {"filename3": {"cluster_item_key": "cluster_item_key"}}}, "/zip/path",
        cluster_items=cluster_items)

    assert result_logs['error'] == {'shared': ["Error processing shared file 'filename1': "
                                               "string indices must be integers"],
                                    'missing': ["Error processing missing file 'filename2': "
                                                "string indices must be integers"]}
    assert result_logs['debug2'] == {'filename1': ["Processing file filename1"],
                                     'filename2': ["Processing file filename2"],
                                     'filename3': ["Remove file: 'filename3'", "File filename3 doesn't exist."]}
    assert result_logs['generic_errors'] == ["Found errors: 1 overwriting, 1 creating and 0 removing"]

    path_join_mock.assert_has_calls([call(core_common.WAZUH_PATH, "filename1"),
                                     call(core_common.WAZUH_PATH, "filename2"),
                                     call(core_common.WAZUH_PATH, "filename3")])
    wazuh_uid_mock.assert_not_called()
    wazuh_gid_mock.assert_not_called()
    mkdir_with_mode_mock.assert_not_called()
    safe_move_mock.assert_not_called()
    open_mock.assert_not_called()
    path_exists_mock.assert_not_called()

    # Reset all mocks
    for mock in all_mocks:
        mock.reset_mock()

    # Now, we are going to test the second for
    worker_handler.cluster_items["files"]["cluster_item_key"]["remove_subdirs_if_empty"] = {
        "dir1": "value1"}
    worker_handler.cluster_items["files"]["excluded_files"] = "dir_files"

    # Test the try
    with patch("os.listdir", return_value="dir_files") as listdir_mock:
        with patch("shutil.rmtree") as rmtree_mock:
            result_logs = worker_handler.update_master_files_in_worker(
                {"extra": {"filename3": {"cluster_item_key": "cluster_item_key"}}}, "/zip/path",
                cluster_items=cluster_items)
            rmtree_mock.assert_called_once()
            listdir_mock.assert_called_once()

            assert result_logs['error'] == defaultdict(list)
            assert result_logs['debug2'] == {'filename3': ["Remove file: 'filename3'",
                                                           "File filename3 doesn't exist."]}
            assert result_logs['generic_errors'] == []
            path_join_mock.assert_has_calls([call(core_common.WAZUH_PATH, "filename3"),
                                             call(core_common.WAZUH_PATH, "")])
            wazuh_uid_mock.assert_not_called()
            wazuh_gid_mock.assert_not_called()
            mkdir_with_mode_mock.assert_not_called()
            safe_move_mock.assert_not_called()
            open_mock.assert_not_called()
            path_exists_mock.assert_not_called()

            # Reset all mocks
            for mock in all_mocks:
                mock.reset_mock()

    # Test the exception
    result_logs = worker_handler.update_master_files_in_worker(
        {"extra": {"filename3": {"cluster_item_key": "cluster_item_key"}}}, "/zip/path",
        cluster_items=cluster_items)

    assert result_logs['error'] == defaultdict(list)
    assert result_logs['debug2'] == {'filename3': ["Remove file: 'filename3'",
                                                   "File filename3 doesn't exist."],
                                     '': ["Error removing directory '': [Errno 2] No such file or directory: "
                                          "'queue/testing_mock/'"]}
    assert result_logs['generic_errors'] == ["Found errors: 0 overwriting, 0 creating and 1 removing"]

    path_join_mock.assert_has_calls([call(core_common.WAZUH_PATH, "filename3"),
                                     call(core_common.WAZUH_PATH, "")])
    wazuh_uid_mock.assert_not_called()
    wazuh_gid_mock.assert_not_called()
    mkdir_with_mode_mock.assert_not_called()
    safe_move_mock.assert_not_called()
    open_mock.assert_not_called()
    path_exists_mock.assert_not_called()


@pytest.mark.asyncio
async def test_worker_handler_get_logger(event_loop):
    """Check if the method 'get_logger' is properly returning the given Logger object."""
    worker_handler = get_worker_handler(event_loop)
    assert isinstance(worker_handler.get_logger(), logging.Logger)


# Test Worker class methods

@pytest.mark.asyncio
@patch("wazuh.core.cluster.worker.metadata.__version__", "1.0.0")
@patch("wazuh.core.cluster.worker.dapi.APIRequestQueue", return_value="APIRequestQueue object")
async def test_worker_init(api_request_queue, event_loop):
    """Check if the object Worker is being properly initialized."""

    task_pool = {'task_pool': ''}
    nested_worker = worker.Worker(configuration=configuration, cluster_items=cluster_items, enable_ssl=False,
                                  performance_test=False, logger=None, concurrency_test=False, file='None', string=20,
                                  task_pool=task_pool)

    assert nested_worker.cluster_name == "wazuh"
    assert nested_worker.node_type == "master"
    assert nested_worker.handler_class == worker.WorkerHandler
    assert "cluster_name" in nested_worker.extra_args
    assert "version" in nested_worker.extra_args
    assert "node_type" in nested_worker.extra_args
    assert nested_worker.extra_args["cluster_name"] == nested_worker.cluster_name
    assert nested_worker.extra_args["version"] == nested_worker.version
    assert nested_worker.extra_args["node_type"] == nested_worker.node_type
    assert nested_worker.dapi == api_request_queue.return_value
    assert nested_worker.version == "1.0.0"


@pytest.mark.asyncio
@patch("wazuh.core.cluster.client.AbstractClientManager.add_tasks", return_value=["task"])
@patch("wazuh.core.cluster.worker.dapi.APIRequestQueue", return_value="APIRequestQueue object")
async def test_worker_add_tasks(api_request_queue, acm_mock, event_loop):
    """Check if the tasks that the worker will run are defined."""

    class DapiMock:
        """Auxiliary class."""

        def __init__(self):
            self.run = "True"

    class ClientMock:
        """Auxiliary class."""

        def __init__(self):
            self.sync_integrity = "0101"
            self.sync_agent_info = "info"

    task_pool = {'task_pool': ''}

    nested_worker = worker.Worker(configuration=configuration, cluster_items=cluster_items, enable_ssl=False,
                                  performance_test=False, logger=None, concurrency_test=False, file='None', string=20,
                                  task_pool=task_pool)

    nested_worker.client = ClientMock()
    nested_worker.dapi = DapiMock()
    assert nested_worker.add_tasks() == ['task', ('0101', ()), ('info', ()), ('True', ())]


@pytest.mark.asyncio
@patch("wazuh.core.cluster.worker.dapi.APIRequestQueue", return_value="APIRequestQueue object")
async def test_worker_get_node(api_request_queue, event_loop):
    """Check if the basic cluster information is returned."""
    task_pool = {'task_pool': ''}

    nested_worker = worker.Worker(configuration=configuration, cluster_items=cluster_items, enable_ssl=False,
                                  performance_test=False, logger=None, concurrency_test=False, file='None', string=20,
                                  task_pool=task_pool)

    assert nested_worker.get_node() == {'type': nested_worker.configuration['node_type'],
                                        'cluster': nested_worker.configuration['name'],
                                        'node': nested_worker.configuration['node_name']}
    api_request_queue.assert_called_once_with(server=nested_worker)
