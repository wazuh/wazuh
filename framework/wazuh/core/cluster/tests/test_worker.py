# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import json
import logging
import sys
from unittest.mock import patch, MagicMock, call

import pytest
import uvloop
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
        from wazuh.core.wdb import WazuhDBConnection

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
loop = asyncio.new_event_loop()
logger = logging.getLogger("wazuh")
cluster_items = {'node': 'master-node',
                 'intervals': {'worker': {'connection_retry': 1, "sync_integrity": 2, "timeout_agent_groups": 0,
                                          "sync_agent_info": 5, "sync_agent_groups": 5,},
                               "communication": {"timeout_receiving_file": 1, "timeout_cluster_request": 20}},
                 "files": {"cluster_item_key": {"remove_subdirs_if_empty": True, "permissions": "value"}}}
configuration = {'node_name': 'master', 'nodes': ['master'], 'port': 1111, "name": "wazuh", "node_type": "master"}


def get_worker_handler():
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


sync_task = cluster_common.SyncTask(b"cmd", logging.getLogger("wazuh"), get_worker_handler())
sync_wazuh_db = cluster_common.SyncWazuhdb(get_worker_handler(), logging.getLogger("wazuh"), b"cmd", "get_command",
                                           "set_command", None)
worker_handler = get_worker_handler()


@patch("asyncio.create_task")
@patch("wazuh.core.cluster.worker.ReceiveAgentGroupsTask.set_up_coro")
def test_rgit_init(set_up_coro_mock, create_task_mock):
    """Test the initialization of the ReceiveAgentGroupsTask object."""

    receive_agent_groups_task = worker.ReceiveAgentGroupsTask(wazuh_common=worker_handler,
                                                              logger=logging.getLogger("wazuh"), task_id="0101")

    assert isinstance(receive_agent_groups_task.wazuh_common, cluster_common.WazuhCommon)
    assert receive_agent_groups_task.task_id == "0101"
    set_up_coro_mock.assert_called_once()
    create_task_mock.assert_called_once()


@patch("asyncio.create_task")
def test_rgit_set_up_coro(create_task_mock):
    """Check if the function is called when the master sends its agent-groups information."""

    class WazuhCommonMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        def recv_agent_groups_local_information(self, wazuh_common, task_id):
            """Auxiliary method."""
            pass

    wazuh_common_mock = WazuhCommonMock()
    receive_agent_groups_task = worker.ReceiveAgentGroupsTask(wazuh_common=wazuh_common_mock,
                                                              logger=logging.getLogger("wazuh"), task_id="0101")
    assert receive_agent_groups_task.set_up_coro() == wazuh_common_mock.recv_agent_groups_local_information
    create_task_mock.assert_called_once()


@patch("asyncio.create_task")
@patch("wazuh.core.cluster.common.ReceiveStringTask.done_callback")
@patch("wazuh.core.cluster.worker.ReceiveAgentGroupsTask.set_up_coro")
def test_rgit_done_callback(set_up_coro_mock, super_callback_mock, create_task_mock):
    """Check if the agent-groups synchronization process was correct."""

    class WazuhCommonMock:
        """Auxiliary class."""

        def __init__(self):
            self.sync_agent_groups_free = None

        def sync_integrity(self, task, info):
            """Auxiliary method."""
            pass

    wazuh_common_mock = WazuhCommonMock()
    receive_agent_groups_task = worker.ReceiveAgentGroupsTask(wazuh_common=wazuh_common_mock,
                                                              logger=logging.getLogger("wazuh"), task_id="0101")
    receive_agent_groups_task.done_callback()

    create_task_mock.assert_called_once()
    super_callback_mock.assert_called_once_with(None)
    set_up_coro_mock.assert_called_once()
    assert wazuh_common_mock.sync_agent_groups_free is True


@patch('asyncio.create_task')
def test_rit_set_up_coro(create_task_mock):
    """Check if a callable is being returned by this method."""

    class WazuhCommonMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        def process_files_from_master(self):
            pass

    receive_task = worker.ReceiveIntegrityTask(wazuh_common=worker_handler, logger=None)
    receive_task.wazuh_common = WazuhCommonMock

    assert receive_task.set_up_coro() == WazuhCommonMock.process_files_from_master
    create_task_mock.assert_called_once()


@patch('asyncio.create_task')
@patch('wazuh.core.cluster.worker.c_common.ReceiveFileTask.done_callback')
def test_rit_done_callback(super_done_callback_mock, create_task_mock):
    """Check if a callable is being returned by this method."""

    class WazuhCommonMock:
        """Auxiliary class."""

        def __init__(self):
            self.check_integrity_free = False

    receive_task = worker.ReceiveIntegrityTask(wazuh_common=worker_handler, logger=None)
    receive_task.wazuh_common = WazuhCommonMock

    receive_task.done_callback()

    create_task_mock.assert_called_once()
    assert receive_task.wazuh_common.check_integrity_free is True
    super_done_callback_mock.assert_called_once()


# Test SyncFiles class methods

@pytest.mark.asyncio
@patch("json.dumps", return_value='')
@patch("os.path.relpath", return_value="path")
@patch("os.unlink", return_value="unlinked path")
@patch("wazuh.core.cluster.cluster.compress_files", return_value="files/path/")
async def test_sync_files_sync_ok(compress_files_mock, unlink_mock, relpath_mock, json_dumps_mock):
    """Check if the methods to synchronize with master are defined."""
    files_to_sync = {"path1": "metadata1"}
    files_metadata = {"path2": "metadata2"}

    class ServerMock:
        """Class used to mock the self.worker value and enter the conditions inside the try."""

        def __init__(self):
            self.name = "Testing"
            self.count = 1

        async def send_request(self, command, data):
            """Decide with will be the right output depending on the scenario."""
            if command == b"cmd" and data == b"" and self.count == 1:
                return b"Error"
            elif command == b"cmd" and data == b"" and self.count == 2:
                return b"OK"
            elif command == b"cmd_e" and b"OK path" and self.count == 2:
                return Exception()
            elif command == b"cmd" and data == b"" and self.count == 3:
                return b"OK"
            elif command == b"cmd_e" and b"OK path" and self.count == 3:
                return b"Error"
            elif command == b"cmd" and data == b"" and self.count == 4:
                return b"OK"
            elif command == b"cmd_e" and b"OK path" and self.count == 4:
                return b"OK"

        async def send_file(self, filename):
            """Auxiliary method."""
            pass

    worker_mock = ServerMock()
    sync_files = worker.SyncFiles(b"cmd", logging.getLogger("wazuh"), worker_mock)

    # Test second condition
    with patch.object(logging.getLogger("wazuh"), "error") as logger_mock:
        await sync_files.sync(files_to_sync, files_metadata)
        json_dumps_mock.assert_called_once_with(
            exception.WazuhClusterError(code=3016, extra_message=str(b"Error")),
            cls=cluster_common.WazuhJSONEncoder)
        logger_mock.assert_called_once_with("Error")

    worker_mock.count = 2
    with patch.object(ServerMock, "send_file") as send_file_mock:
        # Test if present in try and second exception
        with patch.object(logging.getLogger("wazuh"), "debug") as logger_debug_mock:
            with patch.object(logging.getLogger("wazuh"), "error") as logger_error_mock:
                await sync_files.sync(files_to_sync, files_metadata)
                send_file_mock.assert_called_once_with(filename='files/path/')
                logger_debug_mock.assert_has_calls([call(
                    f"Compressing {'files and ' if files_to_sync else ''}'files_metadata.json' of {len(files_metadata)}"
                    f" files."), call("Sending zip file to master."), call("Zip file sent to master.")])
                logger_error_mock.assert_called_once_with("Error sending zip file: ")
                compress_files_mock.assert_called_once_with(name="Testing", list_path=files_to_sync,
                                                            cluster_control_json=files_metadata)
                unlink_mock.assert_called_once_with("files/path/")
                relpath_mock.assert_called_once_with('files/path/', core_common.wazuh_path)
                assert json_dumps_mock.call_count == 2

                # Reset all mocks
                all_mocks = [send_file_mock, logger_debug_mock, logger_error_mock, compress_files_mock, unlink_mock,
                             relpath_mock, json_dumps_mock]
                for mock in all_mocks:
                    mock.reset_mock()

                # Test elif present in try and first exception
                worker_mock.count = 3
                await sync_files.sync(files_to_sync, files_metadata)
                send_file_mock.assert_called_once_with(filename='files/path/')
                logger_debug_mock.assert_has_calls([call(
                    f"Compressing {'files and ' if files_to_sync else ''}'files_metadata.json' of {len(files_metadata)}"
                    f" files."), call("Sending zip file to master."), call("Zip file sent to master.")])
                logger_error_mock.assert_called_once_with(
                    f"Error sending zip file: {exception.WazuhException(3016, 'Error')}")
                compress_files_mock.assert_called_once_with(name="Testing", list_path=files_to_sync,
                                                            cluster_control_json=files_metadata)
                unlink_mock.assert_called_once_with("files/path/")
                relpath_mock.assert_called_once_with('files/path/', core_common.wazuh_path)
                json_dumps_mock.assert_called_once()

                # Reset all mocks
                all_mocks = [send_file_mock, logger_debug_mock, logger_error_mock, compress_files_mock, unlink_mock,
                             relpath_mock, json_dumps_mock]
                for mock in all_mocks:
                    mock.reset_mock()

            # Test return
            worker_mock.count = 4
            assert await sync_files.sync(files_to_sync, files_metadata) is True
            send_file_mock.assert_called_once_with(filename='files/path/')
            logger_debug_mock.assert_has_calls([call(
                f"Compressing {'files and ' if files_to_sync else ''}'files_metadata.json' of {len(files_metadata)}"
                f" files."), call("Sending zip file to master."), call("Zip file sent to master.")])
            compress_files_mock.assert_called_once_with(name="Testing", list_path=files_to_sync,
                                                        cluster_control_json=files_metadata)
            unlink_mock.assert_called_once_with("files/path/")
            relpath_mock.assert_called_once_with('files/path/', core_common.wazuh_path)


@pytest.mark.asyncio
@patch("wazuh.core.cluster.common.Handler.send_request", return_value=Exception())
async def test_sync_files_sync_ko(send_request_mock):
    """Test if the right exceptions are being risen when necessary."""
    files_to_sync = {"path1": "metadata1"}
    files_metadata = {"path2": "metadata2"}
    fernet_key = "00000000000000000000000000000000"

    sync_files = worker.SyncFiles(b"cmd", logging.getLogger("wazuh"),
                                          cluster_common.Handler(fernet_key, cluster_items))

    # Test first condition
    with pytest.raises(Exception):
        await sync_files.sync(files_to_sync, files_metadata)

    send_request_mock.assert_called_once()


# Test WorkerHandler class methods.

def test_worker_handler_init():
    """Test '__init__' method from WorkerHandler class."""

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


@patch("os.path.exists", return_value=False)
@patch("wazuh.core.utils.mkdir_with_mode")
@patch("os.path.join", return_value="/some/path")
@patch("wazuh.core.cluster.worker.client.AbstractClient.connection_result")
def test_worker_handler_connection_result(connection_result_mock, join_mock, mkdir_with_mode_mock, exists_mock):
    """Check if the function is called whenever the master sends a response to the worker's hello command."""

    worker_handler.connected = True
    worker_handler.connection_result("something")
    join_mock.assert_called_once_with(core_common.wazuh_path, "queue", "cluster", "Testing")
    exists_mock.assert_called_once_with("/some/path")
    mkdir_with_mode_mock.assert_called_once_with("/some/path")
    connection_result_mock.assert_called_once()


@patch.object(logging.getLogger("wazuh"), "debug")
def test_worker_handler_process_request_ok(logger_mock):
    """Check if all the command that a worker can receive are being defined."""
    worker_handler.logger = logging.getLogger("wazuh")

    class ClientsMock:
        """Auxiliary class."""

        def send_request(self, command, error_msg):
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
                                              0.0, b'{"updated_chunks": 4, "error_messages": []}'.decode())
            logger_mock.assert_called_with("Command received: 'b'syn_m_a_e''")
    # Test the seventh condition
    with patch("wazuh.core.cluster.master.Master.setup_task_logger",
               worker_handler.setup_task_logger('Agent-groups sync')) as setup_task_logger_mock:
        with patch("wazuh.core.cluster.worker.c_common.end_sending_agent_information",
                   return_value=b"ok") as sync_mock:
            assert worker_handler.process_request(
                command=b"syn_m_g_e", data=b'{"updated_chunks": 4, "error_messages": []}') == b"ok"
            sync_mock.assert_called_once_with(setup_task_logger_mock,
                                              0.0, b'{"updated_chunks": 4, "error_messages": []}'.decode())
            logger_mock.assert_called_with("Command received: 'b'syn_m_g_e''")
    # Test the eighth condition
    with patch("wazuh.core.cluster.worker.c_common.error_receiving_agent_information",
               return_value=b"ok") as error_mock:
        assert worker_handler.process_request(command=b"syn_m_a_err", data=b"data") == b"ok"
        error_mock.assert_called_once_with(
            worker_handler.task_loggers['Agent-info sync'], b"data".decode(), info_type='agent-info')
        logger_mock.assert_called_with("Command received: 'b'syn_m_a_err''")
    # Test the ninth condition
    with patch("wazuh.core.cluster.worker.c_common.error_receiving_agent_information",
               return_value=b"ok") as error_mock:
        assert worker_handler.process_request(command=b"syn_m_g_err", data=b"data") == b"ok"
        error_mock.assert_called_once_with(
            worker_handler.task_loggers['Agent-groups sync'], b"data".decode(), info_type='agent-groups')
        logger_mock.assert_called_with("Command received: 'b'syn_m_g_err''")
    # Test the tenth condition
    with patch("asyncio.create_task", return_value=b"ok") as create_task_mock:
        with patch("wazuh.core.cluster.worker.WorkerHandler.forward_dapi_response",
                   return_value=b"ok") as forward_dapi_mock:
            assert worker_handler.process_request(command=b"dapi_res",
                                                  data=b"data") == (b'ok', b'Response forwarded to worker')
            create_task_mock.assert_called_once()
            forward_dapi_mock.assert_called_with(b"data")
            logger_mock.assert_called_with("Command received: 'b'dapi_res''")

        # Test the eleventh condition
        with patch("wazuh.core.cluster.worker.WorkerHandler.forward_sendsync_response",
                   return_value=b"ok") as forward_sendsync_mock:
            assert worker_handler.process_request(command=b"sendsyn_res",
                                                  data=b"data") == (b'ok', b'Response forwarded to worker')
            forward_sendsync_mock.assert_called_once_with(b"data")
            logger_mock.assert_called_with("Command received: 'b'sendsyn_res''")

        # Test the twelfth condition
        worker_handler.server = ManagerMock()
        with patch.object(ClientsMock, "send_request") as send_request_mock:
            assert worker_handler.process_request(command=b"dapi_err",
                                                  data=b"data 2") == (b'ok', b'DAPI error forwarded to worker')
            send_request_mock.assert_called_once_with(b"dapi_err", b"2")
            logger_mock.assert_called_with("Command received: 'b'dapi_err''")
        # Test the thirteenth condition
        with patch.object(ClientsMock, "send_request") as send_request_mock:
            assert worker_handler.process_request(command=b"sendsyn_err",
                                                  data=b"data 2") == (b'ok', b'SendSync error forwarded to worker')
            send_request_mock.assert_called_once_with(b"err", b"2")
            logger_mock.assert_called_with("Command received: 'b'sendsyn_err''")
    # Test the fourteenth condition
    with patch.object(LocalServerDapiMock, "add_request") as add_request_mock:
        assert worker_handler.process_request(command=b"dapi",
                                              data=b"data") == (b'ok', b'Added request to API requests queue')
        add_request_mock.assert_called_once_with(b"master*data")
        logger_mock.assert_called_with("Command received: 'b'dapi''")
    # Test the fifteenth condition
    with patch("wazuh.core.cluster.worker.client.AbstractClient.process_request",
               return_value=True) as process_request_mock:
        assert worker_handler.process_request(command=b"random", data=b"data") is True
        process_request_mock.assert_called_once_with(b"random", b"data")


@patch.object(logging.getLogger("wazuh"), "debug")
@patch("asyncio.create_task", side_effect=exception.WazuhClusterError(1001))
def test_worker_handler_process_request_ko(create_task_mock, logger_mock):
    """Test the correct exception raise at method 'process_request'."""

    with pytest.raises(exception.WazuhClusterError, match=r".* 3025 .*"):
        worker_handler.process_request(command=b"dapi_err", data=b"data 2")
    logger_mock.assert_called_with("Command received: 'b'dapi_err''")

    with pytest.raises(exception.WazuhClusterError, match=r".* 3025 .*"):
        worker_handler.process_request(command=b"sendsyn_err", data=b"data 2")
    logger_mock.assert_called_with("Command received: 'b'sendsyn_err''")


def test_worker_handler_get_manager():
    """Check if the Worker object is being properly returned."""

    assert isinstance(get_worker_handler().get_manager(), client.AbstractClientManager)


@patch("wazuh.core.cluster.common.WazuhCommon.setup_receive_file", return_value=b"ok")
def test_master_handler_setup_sync_integrity(setup_receive_file_mock):
    """Check if the synchronization process was correctly started."""

    worker_handler = get_worker_handler()

    # Test the first condition
    assert worker_handler.setup_sync_integrity(b'syn_g_m_w', b"data") == b"ok"

    # Test the else condition
    assert worker_handler.setup_sync_integrity(b'unknown', b"data") == b"ok"

    setup_receive_file_mock.has_calls([call(worker.ReceiveAgentGroupsTask, b"ok"), call(None, b"ok")])


@freeze_time('1970-01-01')
@patch.object(logging.getLogger("wazuh.Integrity check"), "info")
@patch("wazuh.core.cluster.common.WazuhCommon.setup_receive_file", return_value="OK")
def test_worker_handler_setup_receive_files_from_master(setup_receive_file_mock, logger_mock):
    """Check is a task was set up to wait until the integrity information has been received from the master and
    processed."""

    worker_handler.integrity_check_status = {"date_start": 0}
    assert worker_handler.setup_receive_files_from_master() == "OK"
    logger_mock.assert_called_once_with("Finished in 0.000s. Sync required.")
    setup_receive_file_mock.assert_called_once()


@patch("wazuh.core.cluster.common.WazuhCommon.end_receiving_file", return_value=(b"OK", b"OK"))
def test_worker_handler_end_receiving_integrity(end_receiving_file_mock):
    """Test if a task was notified about some information reception."""

    assert worker_handler.end_receiving_integrity("file_name") == (b"OK", b"OK")
    end_receiving_file_mock.assert_called_once_with("file_name")


@patch("wazuh.core.cluster.common.WazuhCommon.error_receiving_file", return_value=(b"error", b"error"))
def test_worker_handler_error_receiving_integrity(error_receiving_file_mock):
    """Check if a task was notified about some error that had place during the process."""

    assert worker_handler.error_receiving_integrity("file_name_and_errors") == (b"error", b"error")
    error_receiving_file_mock.assert_called_once_with("file_name_and_errors")


@freeze_time('1970-01-01')
@patch.object(logging.getLogger("wazuh.Integrity check"), "info")
def test_worker_handler_sync_integrity_ok_from_master(logger_mock):
    """Check the correct output message when a command 'sync_m_c_ok' takes place."""

    worker_handler.integrity_check_status = {"date_start": 0}
    assert worker_handler.sync_integrity_ok_from_master() == (b'ok', b'Thanks')
    logger_mock.assert_called_once_with("Finished in 0.000s. Sync not required.")


@pytest.mark.asyncio
@patch("wazuh.core.wdb.socket.socket")
async def test_worker_compare_agent_groups_checksum(socket_mock):
    """Check all the possible cases in the checksum comparison."""

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
    wdb_conn = WazuhDBConnection()
    w_handler = get_worker_handler()
    w_handler.connected = True
    sync_object = cluster_common.SyncWazuhdb(manager=w_handler, logger=logger, cmd=b'syn_g_m_w',
                                             data_retriever=wdb_conn.run_wdb_command,
                                             get_data_command='global sync-agent-groups-get ',
                                             get_payload={"condition": "sync_status", "get_global_hash": True})

    with patch('wazuh.core.cluster.worker.c_common.SyncWazuhdb', return_value=sync_object):
        # There are records that need to be synchronized in the worker. Returns False without comparing checksums.
        async def retrieve_information_callable():
            """Auxiliary method."""

            return ['[{"data": "000111", "hash": "checksum"}]']

        with patch.object(sync_object, 'retrieve_information', side_effect=retrieve_information_callable):
            assert await w_handler.compare_agent_groups_checksums(master_checksum='checksum', logger=logger) == False
            assert 'There is no data requiring synchronization in the local database.' not in logger._debug2

        # There are no records that need synchronization in the worker and the checksums are the same. Returns True.
        async def retrieve_information_callable():
            """Auxiliary method."""

            return ['[{"data": "", "hash": "checksum"}]']

        with patch.object(sync_object, 'retrieve_information', side_effect=retrieve_information_callable):
            assert await w_handler.compare_agent_groups_checksums(master_checksum='checksum', logger=logger) == True
            assert 'There is no data requiring synchronization in the local database.' in logger._debug2

        # There are no records that need synchronization in the worker and the checksums are different.
        # Returns False and sets the counter value to the maximum limit.
        async def retrieve_information_callable():
            """Auxiliary method."""

            return ['[{"data": "", "hash": "checksum_not_equal"}]']

        with patch.object(sync_object, 'retrieve_information', side_effect=retrieve_information_callable):
            assert await w_handler.compare_agent_groups_checksums(master_checksum='checksum', logger=logger) == False
            w_handler.agent_groups_checksum_mismatch_counter = w_handler.agent_groups_checksum_mismatch_limit
            assert 'The master\'s checksum and the worker\'s checksum are different. ' \
                   'Local checksum: checksum_not_equal | Master checksum: checksum.' in logger._debug


@pytest.mark.asyncio
@patch('wazuh.core.cluster.worker.c_common.Handler.send_result_to_manager')
async def test_worker_check_agent_groups_checksums(send_result_to_manager_mock):
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
    worker_handler.agent_groups_checksum_mismatch_counter = 0
    data = {"chunks": ['[{"hash": "a"}]']}

    with patch('wazuh.core.cluster.worker.WorkerHandler.compare_agent_groups_checksums', return_value=False):
        # Check that when the checksums are different the counter is incremented
        await worker_handler.check_agent_groups_checksums(data=data, logger=logger)
        assert worker_handler.agent_groups_checksum_mismatch_counter == 1
        assert 'Checksum comparison failed. Attempt 1/10.' in logger._debug
        assert len(logger._info) == 0

        # Check that when the counter exceeds the maximum limit, the number of attempts is not printed in the logger
        logger.clear()
        worker_handler.agent_groups_checksum_mismatch_counter = worker_handler.agent_groups_checksum_mismatch_limit
        await worker_handler.check_agent_groups_checksums(data=data, logger=logger)
        assert worker_handler.agent_groups_checksum_mismatch_counter == 0
        send_result_to_manager_mock.assert_called_once_with(b'syn_w_g_c', {})
        assert 'Checksum comparison failed. Attempt 11/10.' not in logger._debug
        assert 'Sent request to obtain all agent-groups information from the master node.' in logger._info

    with patch('wazuh.core.cluster.worker.WorkerHandler.compare_agent_groups_checksums', return_value=True):
        # Check that when the checksums are equal, the counter is reset (without previous attempts).
        logger.clear()
        worker_handler.agent_groups_checksum_mismatch_counter = 0
        await worker_handler.check_agent_groups_checksums(data=data, logger=logger)
        assert worker_handler.agent_groups_checksum_mismatch_counter == 0
        assert 'The checksum of both databases match.' in logger._debug

        # Check that when the checksum are equal the counter is reset (with previous attempts).
        logger.clear()
        worker_handler.agent_groups_checksum_mismatch_counter = 1
        await worker_handler.check_agent_groups_checksums(data=data, logger=logger)
        assert worker_handler.agent_groups_checksum_mismatch_counter == 0
        assert 'The checksum of both databases match. Reset the attempt counter.' in logger._debug


@pytest.mark.asyncio
@freeze_time('1970-01-01')
@patch('wazuh.core.cluster.worker.WorkerHandler.check_agent_groups_checksums', return_value='')
@patch('wazuh.core.cluster.common.Handler.send_result_to_manager', return_value='check')
@patch('wazuh.core.cluster.common.Handler.update_chunks_wdb', return_value={'updated_chunks': 1})
@patch('wazuh.core.cluster.common.Handler.get_chunks_in_task_id', return_value='chunks')
async def test_worker_handler_recv_agent_groups_local_information(
        get_chunks_in_task_id_mock, update_chunks_wdb_mock,
        send_result_to_manager_mock, check_agent_groups_checksums_mock):
    """Check that the wazuh-db data reception task is created."""

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._info = []

        def info(self, info):
            self._info.append(info)

    logger = LoggerMock()
    worker_handler = get_worker_handler()
    worker_handler.task_loggers['Agent-groups recv'] = logger

    assert await worker_handler.recv_agent_groups_local_information(task_id=b'17', info_type='agent-groups') == 'check'
    get_chunks_in_task_id_mock.assert_called_once_with(b'17', b'syn_w_g_err')
    update_chunks_wdb_mock.assert_called_once_with('chunks', 'agent-groups', logger, b'syn_w_g_err', 0)
    send_result_to_manager_mock.assert_called_once_with(b'syn_w_g_e', {'updated_chunks': 1})
    check_agent_groups_checksums_mock.assert_called_once_with('chunks', logger)
    assert 'Starting.' in logger._info
    assert 'Finished in 0.000s. Updated 1 chunks.' in logger._info


@pytest.mark.asyncio
@freeze_time('1970-01-01')
@patch("json.dumps", return_value="")
@patch("wazuh.core.cluster.worker.SyncFiles.sync")
@patch.object(logging.getLogger("wazuh.Integrity check"), "error")
@patch("wazuh.core.cluster.cluster.get_files_status", return_value={})
@patch("wazuh.core.cluster.worker.client.common.Handler.send_request")
@patch('wazuh.core.cluster.worker.cluster.run_in_pool', return_value=True)
@patch("wazuh.core.cluster.worker.SyncFiles.request_permission", return_value=True)
async def test_worker_handler_sync_integrity(request_permission_mock, run_in_pool_mock, send_request_mock,
                                             get_files_status, error_mock, sync_mock, json_dumps_mock):
    """Check if files status are correctly obtained and sent to the master."""

    async def asyncio_sleep_mock(delay, result=None, *, loop=None):
        assert delay == worker_handler.cluster_items['intervals']['worker']['sync_agent_info']
        raise Exception()

    class ManagerMock:
        """Auxiliary class."""

        def __init__(self):
            self.task_pool = None

    worker_handler.check_integrity_free = True
    worker_handler.server = ManagerMock()

    # Test the try
    with patch.object(logging.getLogger("wazuh.Integrity check"), "info") as logger_info_mock:
        with patch('asyncio.sleep', asyncio_sleep_mock):
            try:
                await worker_handler.sync_integrity()
            except Exception:
                pass

            request_permission_mock.assert_any_call()
            sync_mock.assert_called_with(files_metadata=worker_handler.check_integrity_free, files_to_sync={})
            logger_info_mock.assert_called_with("Starting.")
            assert worker_handler.integrity_check_status["date_start"] == 0.0

            run_in_pool_mock.side_effect = exception.WazuhException(1001)
            try:
                await worker_handler.sync_integrity()
            except Exception:
                pass

            error_mock.assert_called_with(f"Error synchronizing integrity: {exception.WazuhException(1001)}")
            json_dumps_mock.assert_called_with(exception.WazuhException(1001), cls=cluster_common.WazuhJSONEncoder)
            send_request_mock.assert_called_with(command=b'syn_i_w_m_r', data=b'None ' + "".encode())

            run_in_pool_mock.side_effect = Exception
            try:
                await worker_handler.sync_integrity()
            except Exception:
                pass

            error_mock.assert_called_with("Error synchronizing integrity: ")
            json_dumps_mock.assert_called_with(exception.WazuhClusterError(code=1000, extra_message=str(Exception())),
                                               cls=cluster_common.WazuhJSONEncoder)
            send_request_mock.assert_called_with(command=b'syn_i_w_m_r', data=b'None ' + "".encode())


@pytest.mark.asyncio
@patch("wazuh.core.wdb.socket.socket")
@patch("wazuh.core.cluster.worker.WorkerHandler.general_agent_sync_task")
async def test_worker_handler_setup_sync_agent_info(general_agent_sync_mock, socket_mock):
    """Check that the agent-info task is properly configured."""
    wdb_conn = WazuhDBConnection()
    w_handler = get_worker_handler()
    sync_object = cluster_common.SyncWazuhdb(manager=w_handler, logger=logger, cmd=b'syn_a_w_m',
                                             data_retriever=wdb_conn.run_wdb_command,
                                             get_data_command='global sync-agent-info-get ',
                                             set_data_command='global sync-agent-info-set')

    with patch('wazuh.core.cluster.worker.c_common.SyncWazuhdb', return_value=sync_object):
        await worker_handler.setup_sync_agent_info()
        general_agent_sync_mock.assert_called_with(
            sync_object=sync_object, timer=w_handler.agent_groups_sync_status,
            sleep_interval=w_handler.cluster_items['intervals']['worker']['sync_agent_info'])


@pytest.mark.asyncio
@patch("wazuh.core.wdb.socket.socket")
@patch("wazuh.core.cluster.worker.WorkerHandler.general_agent_sync_task")
async def test_worker_handler_setup_sync_agent_groups(general_agent_sync_mock, socket_mock):
    """Check that the agent-groups task is properly configured."""
    wdb_conn = WazuhDBConnection()
    w_handler = get_worker_handler()
    sync_object = cluster_common.SyncWazuhdb(manager=w_handler, logger=logger, cmd=b'syn_a_w_m',
                                             data_retriever=wdb_conn.run_wdb_command,
                                             get_data_command='global sync-agent-groups-get ',
                                             set_data_command='global sync-agent-groups-set')

    with patch('wazuh.core.cluster.worker.c_common.SyncWazuhdb', return_value=sync_object):
        await worker_handler.setup_sync_agent_groups()
        general_agent_sync_mock.assert_called_with(
            sync_object=sync_object, timer=w_handler.agent_groups_sync_status,
            sleep_interval=w_handler.cluster_items['intervals']['worker']['sync_agent_groups'])


@pytest.mark.asyncio
@patch('wazuh.core.cluster.worker.perf_counter', return_value=0)
@patch("wazuh.core.wdb.socket.socket")
async def test_worker_handler_general_agent_sync_task(socket_mock, perf_counter_mock):
    """Check the functionality of the main loop for the tasks related
    to sending information from the workers database to the master."""

    async def asyncio_sleep_mock(delay, result=None, *, loop=None):
        assert delay == worker_handler.cluster_items['intervals']['worker']['sync_agent_info']
        raise Exception()

    async def request_permission_callable():
        """Auxiliary method."""

        return True

    async def retrieve_information_callable():
        """Auxiliary method."""

        return ['testing']

    async def sync_callable(start_time, chunks):
        """Auxiliary method."""

        return True

    wdb_conn = WazuhDBConnection()
    w_handler = get_worker_handler()
    w_handler.connected = True
    sync_object = cluster_common.SyncWazuhdb(manager=w_handler, logger=logger, cmd=b'syn_a_w_m',
                                             data_retriever=wdb_conn.run_wdb_command,
                                             get_data_command='global sync-agent-groups-get ',
                                             set_data_command='global sync-agent-groups-set')

    with patch.object(sync_object, 'request_permission', side_effect=request_permission_callable):
        with patch.object(sync_object, 'retrieve_information',
                          side_effect=retrieve_information_callable) as retrieve_information_mock:
            with patch.object(sync_object, 'sync', side_effect=sync_callable) as sync_mock:
                with patch.object(sync_object.logger, 'info') as logger_info_mock:
                    with patch.object(sync_object.logger, 'error') as logger_error_mock:
                        with patch('asyncio.sleep', asyncio_sleep_mock):
                            try:
                                await w_handler.general_agent_sync_task(
                                    sync_object=sync_object, timer=w_handler.agent_info_sync_status,
                                    sleep_interval=w_handler.cluster_items['intervals']['worker']['sync_agent_info'])
                            except Exception:
                                pass

                            logger_info_mock.assert_called_with('Starting.')
                            retrieve_information_mock.assert_called_once()
                            perf_counter_mock.assert_called()
                            sync_mock.assert_called_with(start_time=0, chunks=['testing'])
                            assert w_handler.agent_info_sync_status['date_start'] == 0.0

                            sync_mock.side_effect = Exception
                            try:
                                await w_handler.general_agent_sync_task(
                                    sync_object=sync_object, timer=w_handler.agent_info_sync_status,
                                    sleep_interval=w_handler.cluster_items['intervals']['worker']['sync_agent_info'])
                            except Exception:
                                pass
                            logger_error_mock.assert_called_with('Error synchronizing agent information: ')


@pytest.mark.asyncio
@freeze_time('1970-01-01')
@patch.object(logging.getLogger("wazuh.Integrity sync"), "debug")
@patch("wazuh.core.cluster.worker.SyncFiles.sync", return_value=True)
@patch("wazuh.core.cluster.cluster.merge_info", return_value=("n_files", "merged_file"))
async def test_wazuh_handler_sync_extra_valid(merge_info_mock, sync_mock, logger_debug_mock):
    """Test the 'sync_extra_valid' method."""

    extra_valid = {"/missing/path": 0, "missing/path2": 1}
    # Test the try
    with patch.object(logging.getLogger("wazuh.Integrity sync"), "info") as logger_info_mock:
        await worker_handler.sync_extra_valid(extra_valid)
        logger_debug_mock.assert_has_calls([call("Starting sending extra valid files to master."),
                                            call("Finished sending extra valid files in 0.000s.")])
        logger_info_mock.assert_called_once_with("Finished in 0.000s.")
        merge_info_mock.assert_called_once_with(merge_type='agent-groups', node_name="Testing",
                                                files=extra_valid.keys())
        sync_mock.assert_called_once_with(files_to_sync={
            "merged_file": {'merged': True, 'merge_type': 'agent-groups', 'merge_name': "merged_file",
                            'cluster_item_key': 'queue/agent-groups/'}}, files_metadata={
            "merged_file": {'merged': True, 'merge_type': 'agent-groups', 'merge_name': "merged_file",
                            'cluster_item_key': 'queue/agent-groups/'}})

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
@patch("asyncio.wait_for")
@patch("asyncio.create_task")
@patch("json.dumps", return_value="")
@patch("wazuh.core.cluster.cluster.decompress_files")
@patch.object(logging.getLogger("wazuh.Integrity sync"), "info")
@patch.object(logging.getLogger("wazuh.Integrity sync"), "debug")
@patch("wazuh.core.cluster.worker.client.common.Handler.send_request")
@patch("wazuh.core.cluster.worker.WorkerHandler.update_master_files_in_worker")
async def test_worker_handler_process_files_from_master_ok(update_files_mock, send_request_mock, logger_debug_mock,
                                                           logger_info_mock, decompress_files_mock, json_dumps_mock,
                                                           create_task_mock, wait_mock, rmtree_mock):
    """Test if relevant actions are being performed for a file according to its status."""

    class EventMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        @staticmethod
        def wait():
            """Auxiliary method."""
            return "something"

    class TaskMock:
        """Auxiliary class."""

        def __init__(self):
            self.filename = "path of the zip"

    ko_files = [{"shared": "shared_files", "extra_valid": "extra_valid_files", "missing": "missing_files",
                 "extra": "extra files"},
                {"shared": "shared_files", "extra_valid": "", "missing": "missing_files",
                 "extra": "extra files"}]
    zip_path = "/zip/path"

    all_mocks = [update_files_mock, send_request_mock, logger_debug_mock, logger_info_mock, decompress_files_mock,
                 json_dumps_mock, create_task_mock, wait_mock, rmtree_mock]

    # Test try and nested if
    worker_handler.sync_tasks["task_id"] = TaskMock()
    decompress_files_mock.return_value = (ko_files[0], zip_path)
    await worker_handler.process_files_from_master(name="task_id", file_received=EventMock())

    update_files_mock.assert_called_once_with(ko_files[0], zip_path, cluster_items,
                                              worker_handler.task_loggers['Integrity sync'])
    send_request_mock.assert_not_called()
    logger_debug_mock.assert_has_calls(
        [call("Worker does not meet integrity checks. Actions required."), call("Updating local files: Start."),
         call("Updating local files: End."), call("Master requires some worker files.")])
    logger_info_mock.assert_has_calls(
        [call("Starting."),
         call("Files to create: 13 | Files to update: 12 | Files to delete: 11 | Files to send: 17")])
    decompress_files_mock.assert_called_once_with("path of the zip")
    json_dumps_mock.assert_not_called()
    create_task_mock.assert_called_once()
    wait_mock.assert_called_once_with("something", timeout=1)
    rmtree_mock.assert_called_once_with(zip_path)

    # Reset all mocks
    for mock in all_mocks:
        mock.reset_mock()

    # Test try and nested else
    worker_handler.sync_tasks["task_id"] = TaskMock()
    decompress_files_mock.return_value = (ko_files[1], zip_path)
    await worker_handler.process_files_from_master(name="task_id", file_received=EventMock())

    update_files_mock.assert_called_once_with(ko_files[1], zip_path, cluster_items,
                                              worker_handler.task_loggers['Integrity sync'])
    send_request_mock.assert_not_called()
    logger_debug_mock.assert_has_calls(
        [call("Worker does not meet integrity checks. Actions required."), call("Updating local files: Start."),
         call("Updating local files: End.")])
    logger_info_mock.assert_has_calls([
        call("Starting."), call("Files to create: 13 | Files to update: 12 | Files to delete: 11 | Files to send: 0"),
        call("Finished in 0.000s.")])
    decompress_files_mock.assert_called_once_with("path of the zip")
    json_dumps_mock.assert_not_called()
    create_task_mock.assert_not_called()
    wait_mock.assert_called_once_with("something", timeout=1)
    rmtree_mock.assert_called_once_with(zip_path)

    # Reset all mocks
    for mock in all_mocks:
        mock.reset_mock()

    # Test first except
    worker_handler.sync_tasks["task_id"] = TaskMock()
    decompress_files_mock.side_effect = exception.WazuhException(1001)
    await worker_handler.process_files_from_master(name="task_id", file_received=EventMock())

    update_files_mock.assert_not_called()
    send_request_mock.assert_called_once_with(command=b'syn_i_w_m_r', data=b'None ')
    logger_debug_mock.assert_not_called()
    logger_info_mock.assert_called_once_with("Starting.")
    json_dumps_mock.assert_called_once_with(exception.WazuhException(1001), cls=cluster_common.WazuhJSONEncoder)
    create_task_mock.assert_not_called()
    wait_mock.assert_called_once_with("something", timeout=1)
    rmtree_mock.assert_not_called()

    # Reset all mocks
    for mock in all_mocks:
        mock.reset_mock()

    # Test second except
    worker_handler.sync_tasks["task_id"] = TaskMock()
    decompress_files_mock.side_effect = Exception()
    await worker_handler.process_files_from_master(name="task_id", file_received=EventMock())

    update_files_mock.assert_not_called()
    send_request_mock.assert_called_once_with(command=b'syn_i_w_m_r', data=b'None ')
    logger_debug_mock.assert_not_called()
    logger_info_mock.assert_called_once_with("Starting.")
    json_dumps_mock.assert_called_once_with(exception.WazuhClusterError(code=1000, extra_message=str(Exception())),
                                            cls=cluster_common.WazuhJSONEncoder)
    create_task_mock.assert_not_called()
    wait_mock.assert_called_once_with("something", timeout=1)
    rmtree_mock.assert_not_called()


@pytest.mark.asyncio
@patch("asyncio.wait_for")
@patch("json.dumps", return_value="")
@patch("wazuh.core.cluster.worker.client.common.Handler.send_request")
async def test_worker_handler_process_files_from_master_ko(send_request_mock, json_dumps_mock, wait_mock):
    """Test if all the exceptions are being properly handled."""

    class EventMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        @staticmethod
        def wait():
            """Auxiliary class."""
            return "something"

    class TaskMock:
        """Auxiliary class."""

        def __init__(self):
            self.filename = Exception()

    event_mock = EventMock()

    with pytest.raises(Exception):
        worker_handler.sync_tasks["task_id"] = TaskMock()
        await worker_handler.process_files_from_master(name="task_id", file_received=event_mock)

        json_dumps_mock.assert_called_once_with(exception.WazuhClusterError(code=1000, extra_message=str(Exception())),
                                                cls=core.WazuhJSONEncoder)
        send_request_mock.assert_called_once_with(command=b'syn_i_w_m_r', data=b'None ' + "".encode())
        wait_mock.assert_called_once_with(event_mock.wait(),
                                          timeout=cluster_items['intervals']['communication']['timeout_receiving_file'])

    wait_mock.side_effect = Exception
    with pytest.raises(exception.WazuhClusterError, match=r".* 3039 .*"):
        await worker_handler.process_files_from_master(name="task_id", file_received=event_mock)

        send_request_mock.assert_called_once_with(command=b'syn_i_w_m_r', data=b'None ' + "".encode())


@patch("builtins.open")
@patch("os.path.exists", return_value=False)
@patch("wazuh.core.cluster.worker.safe_move")
@patch("wazuh.core.cluster.worker.utils.mkdir_with_mode")
@patch("os.path.join", return_value="queue/agent-groups/")
@patch("wazuh.core.common.wazuh_uid", return_value="wazuh_uid")
@patch("wazuh.core.common.wazuh_gid", return_value="wazuh_gid")
def test_worker_handler_update_master_files_in_worker_ok(wazuh_gid_mock, wazuh_uid_mock, path_join_mock,
                                                         mkdir_with_mode_mock, safe_move_mock, path_exists_mock,
                                                         open_mock):
    """Check if the method is properly receiving and updating files."""

    class LoggerMock:
        """Auxiliary class."""

        def __init__(self):
            self._debug2 = []
            self._debug = []
            self._error = []

        def debug(self, debug):
            self._debug.append(debug)

        def debug2(self, debug):
            self._debug2.append(debug)

        def error(self, error):
            self._error.append(error)

    all_mocks = [wazuh_gid_mock, wazuh_uid_mock, path_join_mock, mkdir_with_mode_mock, safe_move_mock, open_mock,
                 path_exists_mock]

    with patch.object(LoggerMock, "debug") as logger_debug_mock:
        with patch.object(LoggerMock, "debug2") as logger_debug2_mock:
            with patch.object(LoggerMock, "error") as logger_error_mock:
                # As the method has two large for, we will make the condition for the first one equal to something empty
                worker_handler.cluster_items["files"]["cluster_item_key"]["remove_subdirs_if_empty"] = {}

                # Test the first for: for -> if -> for -> try
                # In the nested method, with the first value sent to the 'update_master_files_in_worker' (shared), we
                # are testing the if, meanwhile with the second (missing), we are testing the else.
                with patch("wazuh.core.cluster.cluster.unmerge_info", return_value=[("name", "content", "_")]):
                    with patch("os.remove") as os_remove_mock:
                        worker_handler.update_master_files_in_worker(
                            ko_files={"shared": {
                                "filename1": {"merged": "value", "cluster_item_key": "cluster_item_key"}},
                                "missing": {
                                    "filename1": {"merged": None, "cluster_item_key": "cluster_item_key"}},
                                "extra": {"filename3": {"cluster_item_key": "cluster_item_key"}}}, zip_path="/zip/path",
                            cluster_items=cluster_items, logger=LoggerMock())

                        os_remove_mock.assert_any_call("queue/agent-groups/")
                        logger_error_mock.assert_not_called()
                        logger_debug_mock.assert_has_calls(
                            [call("Received 1 shared files to update from master."),
                             call("Received 1 missing files to update from master.")])
                        logger_debug2_mock.assert_has_calls(
                            [call("Processing file filename1"),
                             call("Processing file filename1"),
                             call("Remove file: 'filename3'")])
                        path_join_mock.assert_has_calls([call(core_common.wazuh_path, 'filename1'),
                                                         call(core_common.wazuh_path, 'name'),
                                                         call(core_common.wazuh_path, 'filename1'),
                                                         call('/zip/path', 'filename1'),
                                                         call(core_common.wazuh_path, 'filename3')])
                        wazuh_uid_mock.assert_called_with()
                        wazuh_gid_mock.assert_called_with()
                        mkdir_with_mode_mock.assert_any_call("queue/agent-groups")
                        assert safe_move_mock.call_count == 2
                        open_mock.assert_called_once()
                        path_exists_mock.assert_called_once()

                        # Reset all mocks
                        for mock in all_mocks:
                            mock.reset_mock()

                # Test the first for: for -> if -> for -> except AND for -> elif -> for -> try -> except -> if
                worker_handler.update_master_files_in_worker(
                    {"shared": {"filename1": "data1"}, "missing": {"filename2": "data2"},
                     "extra": {"filename3": {"cluster_item_key": "cluster_item_key"}}}, "/zip/path",
                    cluster_items=cluster_items, logger=LoggerMock())

                logger_error_mock.assert_has_calls(
                    [call("Error processing shared file 'filename1': string indices must be integers"),
                     call("Error processing missing file 'filename2': string indices must be integers"),
                     call("Found errors: 1 overwriting, 1 creating and 0 removing")])
                logger_debug_mock.assert_has_calls(
                    [call("Received 1 shared files to update from master."),
                     call("Received 1 missing files to update from master."),
                     call("Received 1 shared files to update from master."),
                     call("Received 1 missing files to update from master.")])
                logger_debug2_mock.assert_has_calls(
                    [call("Processing file filename1"),
                     call("Processing file filename1"),
                     call("Remove file: 'filename3'"),
                     call("Processing file filename1"),
                     call("Processing file filename2"),
                     call("Remove file: 'filename3'"),
                     call("File filename3 doesn't exist.")])
                path_join_mock.assert_has_calls([call(core_common.wazuh_path, "filename1"),
                                                 call(core_common.wazuh_path, "filename2"),
                                                 call(core_common.wazuh_path, "filename3")])
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
                path_join_mock.return_value = "queue/agent-groups_mock/"
                worker_handler.update_master_files_in_worker(
                    {"shared": {"filename1": "data1"}, "missing": {"filename2": "data2"},
                     "extra": {"filename3": {"cluster_item_key": "cluster_item_key"}}}, "/zip/path",
                    cluster_items=cluster_items, logger=LoggerMock())

                logger_error_mock.assert_has_calls(
                    [call("Error processing shared file 'filename1': string indices must be integers"),
                     call("Error processing missing file 'filename2': string indices must be integers"),
                     call("Found errors: 1 overwriting, 1 creating and 0 removing"),
                     call("Error processing shared file 'filename1': string indices must be integers"),
                     call("Error processing missing file 'filename2': string indices must be integers"),
                     call("Found errors: 1 overwriting, 1 creating and 1 removing")])
                logger_debug_mock.assert_has_calls(
                    [call("Received 1 shared files to update from master."),
                     call("Received 1 missing files to update from master."),
                     call("Received 1 shared files to update from master."),
                     call("Received 1 missing files to update from master."),
                     call("Received 1 shared files to update from master."),
                     call("Received 1 missing files to update from master."), ])
                logger_debug2_mock.assert_has_calls(
                    [call("Processing file filename1"),
                     call("Processing file filename1"),
                     call("Remove file: 'filename3'"),
                     call("Processing file filename1"),
                     call("Processing file filename2"),
                     call("Remove file: 'filename3'"),
                     call("File filename3 doesn't exist."),
                     call("Processing file filename1"),
                     call("Processing file filename2"),
                     call("Remove file: 'filename3'"),
                     call("Error removing file 'filename3': [Errno 2] No such file or directory: "
                          "'queue/agent-groups_mock/'")])
                path_join_mock.assert_has_calls([call(core_common.wazuh_path, "filename1"),
                                                 call(core_common.wazuh_path, "filename2"),
                                                 call(core_common.wazuh_path, "filename3")])
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
                        worker_handler.update_master_files_in_worker(
                            {"extra": {"filename3": {"cluster_item_key": "cluster_item_key"}}}, "/zip/path",
                            cluster_items=cluster_items, logger=LoggerMock())
                        rmtree_mock.assert_called_once()
                        listdir_mock.assert_called_once()

                        logger_error_mock.assert_has_calls(
                            [call("Error processing shared file 'filename1': string indices must be integers"),
                             call("Error processing missing file 'filename2': string indices must be integers"),
                             call("Found errors: 1 overwriting, 1 creating and 0 removing"),
                             call("Error processing shared file 'filename1': string indices must be integers"),
                             call("Error processing missing file 'filename2': string indices must be integers"),
                             call("Found errors: 1 overwriting, 1 creating and 1 removing"),
                             call("Found errors: 0 overwriting, 0 creating and 1 removing")])
                        logger_debug_mock.assert_has_calls(
                            [call("Received 1 shared files to update from master."),
                             call("Received 1 missing files to update from master."),
                             call("Received 1 shared files to update from master."),
                             call("Received 1 missing files to update from master."),
                             call("Received 1 shared files to update from master."),
                             call("Received 1 missing files to update from master."), ])
                        logger_debug2_mock.assert_has_calls(
                            [call("Processing file filename1"),
                             call("Processing file filename1"),
                             call("Remove file: 'filename3'"),
                             call("Processing file filename1"),
                             call("Processing file filename2"),
                             call("Remove file: 'filename3'"),
                             call("File filename3 doesn't exist."),
                             call("Processing file filename1"),
                             call("Processing file filename2"),
                             call("Remove file: 'filename3'"),
                             call("Error removing file 'filename3': [Errno 2] No such file or directory: "
                                  "'queue/agent-groups_mock/'"),
                             call("Remove file: 'filename3'"),
                             call("Error removing file 'filename3': [Errno 2] No such file or directory: "
                                  "'queue/agent-groups_mock/'")])
                        path_join_mock.assert_has_calls([call(core_common.wazuh_path, "filename3"),
                                                         call(core_common.wazuh_path, "")])
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
                worker_handler.update_master_files_in_worker(
                    {"extra": {"filename3": {"cluster_item_key": "cluster_item_key"}}}, "/zip/path",
                    cluster_items=cluster_items, logger=LoggerMock())

                logger_error_mock.assert_has_calls(
                    [call("Error processing shared file 'filename1': string indices must be integers"),
                     call("Error processing missing file 'filename2': string indices must be integers"),
                     call("Found errors: 1 overwriting, 1 creating and 0 removing"),
                     call("Error processing shared file 'filename1': string indices must be integers"),
                     call("Error processing missing file 'filename2': string indices must be integers"),
                     call("Found errors: 1 overwriting, 1 creating and 1 removing"),
                     call("Found errors: 0 overwriting, 0 creating and 1 removing"),
                     call("Found errors: 0 overwriting, 0 creating and 2 removing")])
                logger_debug_mock.assert_has_calls(
                    [call("Received 1 shared files to update from master."),
                     call("Received 1 missing files to update from master."),
                     call("Received 1 shared files to update from master."),
                     call("Received 1 missing files to update from master."),
                     call("Received 1 shared files to update from master."),
                     call("Received 1 missing files to update from master."), ])
                logger_debug2_mock.assert_has_calls(
                    [call("Processing file filename1"),
                     call("Processing file filename1"),
                     call("Remove file: 'filename3'"),
                     call("Processing file filename1"),
                     call("Processing file filename2"),
                     call("Remove file: 'filename3'"),
                     call("File filename3 doesn't exist."),
                     call("Processing file filename1"),
                     call("Processing file filename2"),
                     call("Remove file: 'filename3'"),
                     call("Error removing file 'filename3': [Errno 2] No such file or directory: "
                          "'queue/agent-groups_mock/'"),
                     call("Remove file: 'filename3'"),
                     call("Error removing file 'filename3': [Errno 2] No such file or directory: "
                          "'queue/agent-groups_mock/'"),
                     call("Remove file: 'filename3'"),
                     call("Error removing file 'filename3': [Errno 2] No such file or directory: "
                          "'queue/agent-groups_mock/'"),
                     call("Error removing directory '': [Errno 2] No such file or directory: "
                          "'queue/agent-groups_mock/'")])
                path_join_mock.assert_has_calls([call(core_common.wazuh_path, "filename3"),
                                                 call(core_common.wazuh_path, "")])
                wazuh_uid_mock.assert_not_called()
                wazuh_gid_mock.assert_not_called()
                mkdir_with_mode_mock.assert_not_called()
                safe_move_mock.assert_not_called()
                open_mock.assert_not_called()
                path_exists_mock.assert_not_called()


def test_worker_handler_get_logger():
    """Check if the method 'get_logger' is properly returning the given Logger object."""

    assert isinstance(worker_handler.get_logger(), logging.Logger)


# Test Worker class methods

@patch('asyncio.get_running_loop', return_value=loop)
@patch("wazuh.core.cluster.worker.metadata.__version__", "1.0.0")
@patch("wazuh.core.cluster.worker.dapi.APIRequestQueue", return_value="APIRequestQueue object")
def test_worker_init(api_request_queue, running_loop_mock):
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


@patch('asyncio.get_running_loop', return_value=loop)
@patch("wazuh.core.cluster.client.AbstractClientManager.add_tasks", return_value=["task"])
@patch("wazuh.core.cluster.worker.dapi.APIRequestQueue", return_value="APIRequestQueue object")
def test_worker_add_tasks(api_request_queue, acm_mock, running_loop_mock):
    """Check if the tasks that the worker will run are defined."""

    class DapiMock:
        """Auxiliary class."""

        def __init__(self):
            self.run = "True"

    class ClientMock:
        """Auxiliary class."""

        def __init__(self):
            self.sync_integrity = "0101"
            self.setup_sync_agent_info = "info"
            self.setup_sync_agent_groups = "groups"

    task_pool = {'task_pool': ''}

    nested_worker = worker.Worker(configuration=configuration, cluster_items=cluster_items, enable_ssl=False,
                                  performance_test=False, logger=None, concurrency_test=False, file='None', string=20,
                                  task_pool=task_pool)

    nested_worker.client = ClientMock()
    nested_worker.dapi = DapiMock()
    assert nested_worker.add_tasks() == ['task', ('0101', ()), ('info', ()), ('groups', ()), ('True', ())]


@patch('asyncio.get_running_loop', return_value=loop)
@patch("wazuh.core.cluster.worker.dapi.APIRequestQueue", return_value="APIRequestQueue object")
def test_worker_get_node(api_request_queue, running_loop_mock):
    """Check if the basic cluster information is returned."""
    task_pool = {'task_pool': ''}

    nested_worker = worker.Worker(configuration=configuration, cluster_items=cluster_items, enable_ssl=False,
                                  performance_test=False, logger=None, concurrency_test=False, file='None', string=20,
                                  task_pool=task_pool)

    assert nested_worker.get_node() == {'type': nested_worker.configuration['node_type'],
                                        'cluster': nested_worker.configuration['name'],
                                        'node': nested_worker.configuration['node_name']}
    api_request_queue.assert_called_once_with(server=nested_worker)
    running_loop_mock.assert_called_once()
