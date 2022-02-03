# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import json
import logging
import sys
from unittest.mock import patch, MagicMock, call, ANY

import pytest
import uvloop
import wazuh.core.exception as exception
from freezegun import freeze_time

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.core.cluster import client, worker, common
        from wazuh.core import common as core_common

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
loop = asyncio.new_event_loop()
logger = logging.getLogger("wazuh")
cluster_items = {'node': 'master-node',
                 'intervals': {'worker': {'connection_retry': 1, "sync_integrity": 2, "sync_agent_info": 5},
                               "communication": {"timeout_receiving_file": 1}},
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


sync_task = worker.SyncTask(b"cmd", logging.getLogger("wazuh"), get_worker_handler())
sync_wazuh_db = worker.SyncWazuhdb(get_worker_handler(), logging.getLogger("wazuh"), b"cmd", "get_command",
                                   "set_command", None)
worker_handler = get_worker_handler()


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


# Test SyncTask class methods

def test_sync_task_init():
    """Test '__init__' method from the SyncTask class."""

    assert sync_task.cmd == b"cmd"
    assert sync_task.logger == logging.getLogger("wazuh")
    assert isinstance(sync_task.worker, worker.WorkerHandler)


@pytest.mark.asyncio
@patch('wazuh.core.cluster.worker.WorkerHandler.send_request', return_value=Exception())
async def test_sync_task_request_permission(send_request_mock):
    """Check if a True value is returned once a permission to start synchronization is granted or a False when it
    is not."""

    # Test first condition
    with patch.object(logging.getLogger("wazuh"), "error") as logger_mock:
        assert await sync_task.request_permission() is False
        send_request_mock.assert_called_with(command=b"cmd" + b"_p", data=b"")
        logger_mock.assert_called_once_with(f"Error asking for permission: {Exception()}")

    with patch.object(logging.getLogger("wazuh"), "debug") as logger_mock:
        # Test second condition
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

    with pytest.raises(NotImplementedError):
        await sync_task.sync()


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

    class WorkerMock:
        """Class used to mock the self.worker value and enter the conditions inside the try."""

        def __init__(self):
            self.name = "Testing"
            self.count = 1
            self.interrupted_tasks = {b'OK', b'abcd'}

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

    worker_mock = WorkerMock()
    sync_files = worker.SyncFiles(b"cmd", logging.getLogger("wazuh"), worker_mock)

    # Test second condition
    with patch.object(logging.getLogger("wazuh"), "error") as logger_mock:
        await sync_files.sync(files_to_sync, files_metadata)
        json_dumps_mock.assert_called_once_with(
            exception.WazuhClusterError(code=3016, extra_message=str(b"Error")),
            cls=common.WazuhJSONEncoder)
        logger_mock.assert_called_once_with("Error")

    worker_mock.count = 2
    with patch.object(WorkerMock, "send_file") as send_file_mock:
        # Test if present in try and second exception
        with patch.object(logging.getLogger("wazuh"), "debug") as logger_debug_mock:
            with patch.object(logging.getLogger("wazuh"), "error") as logger_error_mock:
                await sync_files.sync(files_to_sync, files_metadata)
                send_file_mock.assert_called_once_with(filename='files/path/', task_id=b'OK')
                logger_debug_mock.assert_has_calls([call(
                    f"Compressing {'files and ' if files_to_sync else ''}'files_metadata.json' of {len(files_metadata)}"
                    f" files."), call("Sending zip file to master."), call("Zip file sent to master.")])
                logger_error_mock.assert_called_once_with("Error sending zip file: ")
                compress_files_mock.assert_has_calls([call(name="Testing", list_path=files_to_sync,
                                                           cluster_control_json=files_metadata)]*2)
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
                send_file_mock.assert_called_once_with(filename='files/path/', task_id=b'OK')
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
            send_file_mock.assert_called_once_with(filename='files/path/', task_id=b'OK')
            logger_debug_mock.assert_has_calls([call(
                f"Compressing {'files and ' if files_to_sync else ''}'files_metadata.json' of {len(files_metadata)}"
                f" files."), call("Sending zip file to master."), call("Zip file sent to master.")])
            compress_files_mock.assert_called_once_with(name="Testing", list_path=files_to_sync,
                                                        cluster_control_json=files_metadata)
            unlink_mock.assert_called_once_with("files/path/")
            relpath_mock.assert_called_once_with('files/path/', core_common.wazuh_path)

            assert worker_mock.interrupted_tasks == {b'abcd'}


@pytest.mark.asyncio
@patch("wazuh.core.cluster.worker.WorkerHandler.send_request", return_value=Exception())
async def test_sync_files_sync_ko(send_request_mock):
    """Test if the right exceptions are being risen when necessary."""
    files_to_sync = {"path1": "metadata1"}
    files_metadata = {"path2": "metadata2"}

    sync_files = worker.SyncFiles(b"cmd", logging.getLogger("wazuh"), get_worker_handler())

    # Test first condition
    with pytest.raises(Exception):
        await sync_files.sync(files_to_sync, files_metadata)

    send_request_mock.assert_called_once()


# Test SyncWazuhdb class

def test_sync_wazuh_db_init():
    """Test the '__init__' method from the SyncWazuhdb class."""

    assert sync_wazuh_db.get_data_command == "get_command"
    assert sync_wazuh_db.set_data_command == "set_command"
    assert sync_wazuh_db.data_retriever is None


@pytest.mark.asyncio
@freeze_time('1970-01-01')
@patch("json.dumps", return_value="")
@patch('wazuh.core.cluster.worker.cluster.run_in_pool', return_value=True)
async def test_sync_wazuh_db_sync_ok(run_in_pool_mock, json_dumps_mock):
    """Check if the information is being properly sent to the master node."""
    chunks = True

    def callable_mock(data):
        """Mock method in order to obtain a particular output."""
        if chunks:
            return [data]
        else:
            return []

    sync_wazuh_db.data_retriever = callable_mock

    # Test try and if
    with patch.object(logging.getLogger("wazuh"), "debug") as logger_debug_mock:
        with patch("wazuh.core.cluster.worker.WorkerHandler.send_string", return_value=b"OK") as send_string_mock:
            with patch("wazuh.core.cluster.worker.WorkerHandler.send_request") as send_request_mock:
                assert await sync_wazuh_db.sync(start_time=10) is True
                send_request_mock.assert_called_once_with(command=b"cmd", data=b"OK")
                json_dumps_mock.assert_called_with({"set_data_command": "set_command", "chunks": ["get_command"]})
                logger_debug_mock.assert_has_calls(
                    [call(f"Obtained {1} chunks of data in 0.000s."), call(f"All chunks sent.")])

            send_string_mock.assert_called_with(b"")

            # Test except
        logger_debug_mock.side_effect = exception.WazuhException(1001)
        with patch.object(logging.getLogger("wazuh"), "error") as logger_error_mock:
            assert await sync_wazuh_db.sync(start_time=10) is None
            logger_error_mock.assert_called_once_with(
                f"Error obtaining data from wazuh-db: {exception.WazuhException(1001)}")

    # Test else
    chunks = False
    with patch.object(logging.getLogger("wazuh"), "info") as logger_info_mock:
        assert await sync_wazuh_db.sync(start_time=10) is True
        logger_info_mock.assert_called_once_with(f"Finished in -10.000s (0 chunks sent).")


@pytest.mark.asyncio
@freeze_time('1970-01-01')
@patch("json.dumps", return_value="")
@patch.object(logging.getLogger("wazuh"), "debug")
@patch("wazuh.core.cluster.worker.WorkerHandler.send_string", return_value=b"Error")
async def test_sync_wazuh_db_sync_ko(send_string_mock, logger_debug_mock, json_dumps_mock):
    """Test if the proper exceptions are raised when needed."""

    def callable_mock(data):
        """Mock method in order to obtain a particular output."""
        return [data]

    sync_wazuh_db.data_retriever = callable_mock

    # Test try and if
    with pytest.raises(exception.WazuhClusterError, match=r".* 3016 .*"):
        await sync_wazuh_db.sync(start_time=10)
        json_dumps_mock.assert_called_with({"set_data_command": "set_command", "chunks": ["get_command"]})
        logger_debug_mock.assert_called_once_with(f"Obtained {1} chunks of data in 0.000s.")

    send_string_mock.assert_called_with(b"")


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
    with patch("wazuh.core.cluster.worker.WorkerHandler.sync_agent_info_from_master",
               return_value=b"ok") as sync_mock:
        assert worker_handler.process_request(command=b"syn_m_a_e", data=b"data") == b"ok"
        sync_mock.assert_called_once_with(b"data".decode())
        logger_mock.assert_called_with("Command received: 'b'syn_m_a_e''")
    # Test the sixth condition
    with patch("wazuh.core.cluster.worker.WorkerHandler.error_receiving_agent_info",
               return_value=b"ok") as error_mock:
        assert worker_handler.process_request(command=b"syn_m_a_err", data=b"data") == b"ok"
        error_mock.assert_called_once_with(b"data".decode())
        logger_mock.assert_called_with("Command received: 'b'syn_m_a_err''")
    # Test the seventh condition
    with patch("asyncio.create_task", return_value=b"ok") as create_task_mock:
        with patch("wazuh.core.cluster.worker.WorkerHandler.forward_dapi_response",
                   return_value=b"ok") as forward_dapi_mock:
            assert worker_handler.process_request(command=b"dapi_res",
                                                  data=b"data") == (b'ok', b'Response forwarded to worker')
            create_task_mock.assert_called_once()
            forward_dapi_mock.assert_called_with(b"data")
            logger_mock.assert_called_with("Command received: 'b'dapi_res''")

        # Test the eighth condition
        with patch("wazuh.core.cluster.worker.WorkerHandler.forward_sendsync_response",
                   return_value=b"ok") as forward_sendsync_mock:
            assert worker_handler.process_request(command=b"sendsyn_res",
                                                  data=b"data") == (b'ok', b'Response forwarded to worker')
            forward_sendsync_mock.assert_called_once_with(b"data")
            logger_mock.assert_called_with("Command received: 'b'sendsyn_res''")

        # Test the ninth condition
        worker_handler.manager = ManagerMock()
        with patch.object(ClientsMock, "send_request") as send_request_mock:
            assert worker_handler.process_request(command=b"dapi_err",
                                                  data=b"data 2") == (b'ok', b'DAPI error forwarded to worker')
            send_request_mock.assert_called_once_with(b"dapi_err", b"2")
            logger_mock.assert_called_with("Command received: 'b'dapi_err''")
        # Test the tenth condition
        with patch.object(ClientsMock, "send_request") as send_request_mock:
            assert worker_handler.process_request(command=b"sendsyn_err",
                                                  data=b"data 2") == (b'ok', b'SendSync error forwarded to worker')
            send_request_mock.assert_called_once_with(b"err", b"2")
            logger_mock.assert_called_with("Command received: 'b'sendsyn_err''")
    # Test the eleventh condition
    with patch.object(LocalServerDapiMock, "add_request") as add_request_mock:
        assert worker_handler.process_request(command=b"dapi",
                                              data=b"data") == (b'ok', b'Added request to API requests queue')
        add_request_mock.assert_called_once_with(b"master*data")
        logger_mock.assert_called_with("Command received: 'b'dapi''")
    # Test the twelfth condition
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


@freeze_time('1970-01-01')
@patch("json.loads", return_value={"updated_chunks": 10, "error_messages": None})
def test_worker_handler_sync_agent_info_from_master(json_loads_mock):
    """Check the correct output message when a command 'syn_m_a_e' takes place."""

    worker_handler.agent_info_sync_status = {"date_start": 0}

    with patch.object(logging.getLogger("wazuh.Agent-info sync"), "info") as logger_info_mock:
        assert worker_handler.sync_agent_info_from_master("response") == (b'ok', b'Thanks')
        json_loads_mock.assert_called_once_with("response")
        logger_info_mock.assert_called_once_with("Finished in 0.000s (10 chunks updated).")

    with patch.object(logging.getLogger("wazuh.Agent-info sync"), "error") as logger_error_mock:
        json_loads_mock.return_value = {"updated_chunks": 10, "error_messages": "error"}
        assert worker_handler.sync_agent_info_from_master("response") == (b'ok', b'Thanks')
        logger_error_mock.assert_called_once_with(
            "Finished in 0.000s (10 chunks updated). There were 5 chunks with errors: error")


@patch.object(logging.getLogger("wazuh.Agent-info sync"), "error")
def test_worker_handler_error_receiving_agent_info(logger_mock):
    """Check the correct output message when a command 'syn_m_a_err' takes place."""

    assert worker_handler.error_receiving_agent_info("response") == (b'ok', b'Thanks')
    logger_mock.assert_called_once_with("There was an error while processing agent-info on the master: response")


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
    worker_handler.manager = ManagerMock()

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
            json_dumps_mock.assert_called_with(exception.WazuhException(1001), cls=common.WazuhJSONEncoder)
            send_request_mock.assert_called_with(command=b'syn_i_w_m_r', data=b'None ' + "".encode())

            run_in_pool_mock.side_effect = Exception
            try:
                await worker_handler.sync_integrity()
            except Exception:
                pass

            error_mock.assert_called_with("Error synchronizing integrity: ")
            json_dumps_mock.assert_called_with(exception.WazuhClusterError(code=1000, extra_message=str(Exception())),
                                               cls=common.WazuhJSONEncoder)
            send_request_mock.assert_called_with(command=b'syn_i_w_m_r', data=b'None ' + "".encode())


@pytest.mark.asyncio
@freeze_time('1970-01-01')
@patch("wazuh.core.wdb.socket.socket")
@patch("wazuh.core.wdb.WazuhDBConnection._send")
@patch("wazuh.core.wdb.WazuhDBConnection.execute")
@patch("wazuh.core.cluster.worker.SyncWazuhdb.sync")
@patch("wazuh.core.wdb.WazuhDBConnection.run_wdb_command")
@patch.object(logging.getLogger("wazuh.Agent-info sync"), "info")
@patch.object(logging.getLogger("wazuh.Agent-info sync"), "error")
@patch("wazuh.core.cluster.worker.SyncWazuhdb.request_permission")
async def test_worker_handler_sync_agent_info(request_permission_mock, logger_error_mock, logger_info_mock,
                                              run_wdb_command_mock, sync_mock, execute_mock, send_mock, socket_mock):
    """Check if information is obtained from this worker and send to manager."""

    async def asyncio_sleep_mock(delay, result=None, *, loop=None):
        assert delay == worker_handler.cluster_items['intervals']['worker']['sync_agent_info']
        raise Exception()

    async def request_permission_callable():
        """Auxiliary method."""

        return True

    async def sync_callable(start_time):
        """Auxiliary method."""

        return True

    request_permission_mock.return_value = request_permission_callable
    sync_mock.return_value = sync_callable

    with patch('asyncio.sleep', asyncio_sleep_mock):
        try:
            await worker_handler.sync_agent_info()
        except Exception:
            pass

        logger_info_mock.assert_called_with('Starting.')
        sync_mock.assert_called_with(start_time=0)
        assert worker_handler.agent_info_sync_status['date_start'] == 0.0

        sync_mock.side_effect = Exception
        try:
            await worker_handler.sync_agent_info()
        except Exception:
            pass

        logger_error_mock.assert_called_with("Error synchronizing agent info: ")


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
            cls = common.WazuhJSONEncoder
            await worker_handler.sync_extra_valid(extra_valid)
            logger_debug_mock.assert_called_with("Starting sending extra valid files to master.")
            logger_error_mock.assert_called_once_with(
                f"Error synchronizing extra valid files: {exception.WazuhException(1001)}")
            send_request_mock.assert_called_once_with(command=b'syn_i_w_m_r',
                                                      data=b'None ' + json.dumps(exception.WazuhException(1001),
                                                                                 cls=cls).encode())
            # Test second exception
            with patch("json.dumps", return_value="data_to_encode") as json_mock:
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
    json_dumps_mock.assert_called_once_with(exception.WazuhException(1001), cls=common.WazuhJSONEncoder)
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
                                            cls=common.WazuhJSONEncoder)
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
    json_dumps_mock.assert_called_with(exception.WazuhClusterError(code=1000, extra_message=str(Exception())),
                                       cls=common.WazuhJSONEncoder)
    send_request_mock.assert_called_with(command=b'syn_i_w_m_r', data=b'None ')
    wait_mock.assert_called_once_with(event_mock.wait(),
                                      timeout=cluster_items['intervals']['communication']['timeout_receiving_file'])

    wait_mock.side_effect = Exception
    with pytest.raises(exception.WazuhClusterError, match=r".* 3039 .*"):
        await worker_handler.process_files_from_master(name="task_id", file_received=event_mock)
    send_request_mock.assert_called_with(command=b'cancel_task', data=b'task_id ')


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
            self.sync_agent_info = "info"

    task_pool = {'task_pool': ''}

    nested_worker = worker.Worker(configuration=configuration, cluster_items=cluster_items, enable_ssl=False,
                                  performance_test=False, logger=None, concurrency_test=False, file='None', string=20,
                                  task_pool=task_pool)

    nested_worker.client = ClientMock()
    nested_worker.dapi = DapiMock()
    assert nested_worker.add_tasks() == ['task', ('0101', ()), ('info', ()), ('True', ())]


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
