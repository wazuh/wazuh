# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import logging
import os
import sys
from unittest.mock import patch, mock_open, MagicMock, call

import pytest
import uvloop

from wazuh.core.exception import WazuhException

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.core.cluster import client, worker
        from wazuh.core import common

old_basic_ck = """001 test1 any 54cfda3bfcc817aadc8f317b3f05d676d174cdf893aa2f9ee2a302ef17ae6794
002 test2 any 7a9c0990dadeca159c239a06031b04d462d6d28dd59628b41dc7e13cc4d3a344
003 test3 any d7ae2f7fe182d202f9088ecb7a0c8899fee7f192c0c0d2d4db906d5fc22a7ad5"""

new_ck_purge = """003 test3 any d7ae2f7fe182d202f9088ecb7a0c8899fee7f192c0c0d2d4db906d5fc22a7ad5
002 test2 any 7a9c0990dadeca159c239a06031b04d462d6d28dd59628b41dc7e13cc4d3a344"""

new_ck_purge2 = "003 test3 any d7ae2f7fe182d202f9088ecb7a0c8899fee7f192c0c0d2d4db906d5fc22a7ad5\n"

new_ck_no_purge = """001 !test1 any 54cfda3bfcc817aadc8f317b3f05d676d174cdf893aa2f9ee2a302ef17ae6794
002 test2 any 7a9c0990dadeca159c239a06031b04d462d6d28dd59628b41dc7e13cc4d3a344
003 test3 any d7ae2f7fe182d202f9088ecb7a0c8899fee7f192c0c0d2d4db906d5fc22a7ad5"""

new_ck_no_purge2 = """001 !test1 any 54cfda3bfcc817aadc8f317b3f05d676d174cdf893aa2f9ee2a302ef17ae6794
002 !test2 any 7a9c0990dadeca159c239a06031b04d462d6d28dd59628b41dc7e13cc4d3a344
003 test3 any d7ae2f7fe182d202f9088ecb7a0c8899fee7f192c0c0d2d4db906d5fc22a7ad5"""

new_ck_more_agents = """001 test1 any 54cfda3bfcc817aadc8f317b3f05d676d174cdf893aa2f9ee2a302ef17ae6794
002 test2 any 7a9c0990dadeca159c239a06031b04d462d6d28dd59628b41dc7e13cc4d3a344
003 test3 any d7ae2f7fe182d202f9088ecb7a0c8899fee7f192c0c0d2d4db906d5fc22a7ad5
004 test4 any d7ae2f7fe182d202f9088ecb7a0f8899fee7f192c0c0d2d4db906dtfc22a7ad5"""

new_ck_more_agents_purge = """003 test3 any d7ae2f7fe182d202f9088ecb7a0c8899fee7f192c0c0d2d4db906d5fc22a7ad5
002 test2 any 7a9c0990dadeca159c239a06031b04d462d6d28dd59628b41dc7e13cc4d3a344
004 test4 any d7ae2f7fe182d202f9088ecb7a0f8899fee7f192c0c0d2d4db906dtfc22a7ad5"""

new_ck_more_agents_no_purge = """001 !test1 any 54cfda3bfcc817aadc8f317b3f05d676d174cdf893aa2f9ee2a302ef17ae6794
002 test2 any 7a9c0990dadeca159c239a06031b04d462d6d28dd59628b41dc7e13cc4d3a344
003 test3 any d7ae2f7fe182d202f9088ecb7a0c8899fee7f192c0c0d2d4db906d5fc22a7ad5
004 test4 any d7ae2f7fe182d202f9088ecb7a0f8899fee7f192c0c0d2d4db906dtfc22a7ad5"""


def AsyncMock(*args, **kwargs):
    m = MagicMock(*args, **kwargs)

    async def mock_coro(*args, **kwargs):
        return m(*args, **kwargs)

    mock_coro.mock = m
    return mock_coro


@pytest.mark.parametrize('old_ck, new_ck, agents_to_remove', [
    (old_basic_ck, new_ck_purge, {'001'}),
    (old_basic_ck, new_ck_purge2, {'001', '002'}),
    (old_basic_ck, new_ck_no_purge, {'001'}),
    (old_basic_ck, new_ck_no_purge2, {'001', '002'}),
    (old_basic_ck, '\n', {'001', '002', '003'}),
    ('\n', old_basic_ck, set()),
    (old_basic_ck, new_ck_more_agents, set()),
    (old_basic_ck, new_ck_more_agents_purge, {'001'}),
    (old_basic_ck, new_ck_more_agents_no_purge, {'001'})
])
@patch('wazuh.core.cluster.worker.WorkerHandler.remove_bulk_agents')
def test_check_removed_agents(remove_agents_patch, old_ck, new_ck, agents_to_remove):
    """
    Tests WorkerHandler._check_removed_agents function.
    """
    # Custom mock_open object to be able to read multiple files contents (old and new client keys)
    mock_files = [mock_open(read_data=content).return_value for content in [old_ck, new_ck]]
    mock_opener = mock_open()
    mock_opener.side_effect = mock_files

    root_logger = logging.getLogger()

    with patch('builtins.open', mock_opener):
        worker.WorkerHandler._check_removed_agents('/random/path/client.keys', root_logger)

        remove_agents_patch.assert_called_once_with(agents_to_remove, root_logger)


@pytest.mark.parametrize('agents_to_remove', [
    {'001'},
    [str(x).zfill(3) for x in range(1, 15)]
])
@patch('wazuh.core.cluster.worker.WazuhDBConnection')
@patch('shutil.rmtree')
@patch('os.remove')
@patch('glob.iglob')
@patch('wazuh.core.agent.Agent.get_agents_overview')
@patch('wazuh.core.cluster.worker.Connection')
@patch('os.path.isdir')
def test_remove_bulk_agents(isdir_mock, connection_mock, agents_mock, glob_mock, remove_mock, rmtree_mock, wdb_mock,
                            agents_to_remove):
    """
    Tests WorkerHandler.remove_bulk_agents function.
    """
    agents_mock.return_value = {'totalItems': len(agents_to_remove),
                                'items': [{'id': a_id, 'ip': '0.0.0.0', 'name': 'test'} for a_id in agents_to_remove]}
    files_to_remove = [common.ossec_path + '/queue/rootcheck/({name}) {ip}->rootcheck',
                       common.ossec_path + '/queue/diff/{name}', common.ossec_path + '/queue/agent-groups/{id}',
                       common.ossec_path + '/queue/rids/{id}', common.ossec_path + '/var/db/agents/{name}-{id}.db',
                       'global.db']
    glob_mock.side_effect = [[f.format(id=a, ip='0.0.0.0', name='test') for a in agents_to_remove] for f in
                             files_to_remove]
    root_logger = logging.getLogger()
    root_logger.debug2 = root_logger.debug
    isdir_mock.side_effect = lambda x: x == 'queue/diff/test'

    worker.WorkerHandler.remove_bulk_agents(agents_to_remove, root_logger)

    for f in files_to_remove:
        if f == 'global.db':
            continue
        for a in agents_to_remove:
            file_name = f.format(id=a, ip='0.0.0.0', name='test')
            (rmtree_mock if f == 'queue/diff/{name}' else remove_mock).assert_any_call(file_name)


asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
loop = asyncio.new_event_loop()
logger = None


@pytest.fixture(scope='module')
def create_log(request):
    current_logger_path = os.path.join(os.path.dirname(__file__), 'testing.log')
    logging.basicConfig(filename=current_logger_path, level=logging.DEBUG)
    setattr(request.module, 'logger', logging.getLogger('test'))
    yield
    os.path.exists(current_logger_path) and os.remove(current_logger_path)


def get_worker_handler():
    with patch('asyncio.get_running_loop', return_value=loop):
        abstract_client = client.AbstractClientManager(configuration={'node_name': 'master', 'nodes': ['master'],
                                                                      'port': 1111},
                                                       cluster_items={'node': 'master-node',
                                                                      'intervals': {'worker': {'connection_retry': 1}}},
                                                       enable_ssl=False, performance_test=False, logger=None,
                                                       concurrency_test=False, file='None', string=20)

    return worker.WorkerHandler(cluster_name='Testing', node_type='master', version='4.0.0',
                                loop=loop, on_con_lost=None, name='Testing',
                                fernet_key='01234567891011121314151617181920', logger=logger,
                                manager=abstract_client, cluster_items={'node': 'master-node'})


def test_ReceiveIntegrityTask():
    worker_handler = get_worker_handler()

    with patch('asyncio.create_task', side_effect=None):
        with patch('wazuh.core.cluster.common.ReceiveFileTask.set_up_coro', side_effect=None):
            receive_task = worker.ReceiveIntegrityTask(wazuh_common=worker_handler, logger=None)
            assert receive_task.set_up_coro()


@pytest.mark.asyncio
async def test_SyncWorker(create_log, caplog):
    async def check_message(mock, expected_message):
        with patch('wazuh.core.cluster.common.Handler.send_request', new=AsyncMock(return_value=mock)):
            with caplog.at_level(logging.DEBUG):
                await sync_worker.sync()
                assert caplog.records[-1].message == expected_message

    worker_handler = get_worker_handler()

    sync_worker = worker.SyncWorker(cmd=b'testing', files_to_sync={'files': ['testing']}, checksums={'testing': '0'},
                                    logger=logger, worker=worker_handler)

    send_request_mock = KeyError(1)
    await check_message(mock=send_request_mock, expected_message=f"Error asking for permission: 1")
    await check_message(mock=b'False', expected_message="Master didnt grant permission to synchronize")
    await check_message(mock=b'True', expected_message="Worker files sent to master")

    error = WazuhException(1001)
    with patch('wazuh.core.cluster.common.Handler.send_request', new=AsyncMock(return_value=b'True')):
        with patch('wazuh.core.cluster.common.Handler.send_file', new=AsyncMock(side_effect=error)):
            await sync_worker.sync()
            assert 'Error sending files information' in caplog.records[-1].message

    error = KeyError(1)
    with patch('wazuh.core.cluster.common.Handler.send_request', new=AsyncMock(return_value=b'True')):
        with patch('wazuh.core.cluster.common.Handler.send_file', new=AsyncMock(side_effect=error)):
            await sync_worker.sync()
            assert 'Error sending files information' in caplog.records[-1].message


@pytest.mark.asyncio
async def test_SyncInfo(caplog):
    async def check_message(expected_messages, *args, **kwargs):
        with caplog.at_level(logging.DEBUG):
            await sync_worker.retrieve_and_send(*args, **kwargs)
            for i, expected_message in enumerate(expected_messages):
                assert caplog.records[-(i+1)].message == expected_message

    worker_handler = get_worker_handler()

    # Test if data_retriever exceptions are handled
    sync_worker = worker.RetrieveAndSendToMaster(worker=worker_handler, destination_daemon='test', logger=logger,
                                                 data_retriever=lambda: exec('raise(WazuhException(1000))'))
    await check_message(expected_messages=["Error obtaining data: Error 1000 - Wazuh Internal Error",
                                           "Obtaining data to be sent to master's test."])

    # Test params used in data_retriever are correct
    data_mock = MagicMock()
    sync_worker = worker.RetrieveAndSendToMaster(worker=worker_handler, destination_daemon='test', logger=logger,
                                                 data_retriever=data_mock)
    await check_message(expected_messages=[], command='global sql test')
    data_mock.assert_called_once_with(command='global sql test')

    # Test expected exception is raised when calling LocalClient.execute().
    sync_worker = worker.RetrieveAndSendToMaster(worker=worker_handler, destination_daemon='test', logger=logger,
                                                 data_retriever=lambda: ['test'])
    with patch('wazuh.core.cluster.local_client.LocalClient.execute', side_effect=WazuhException(1000)):
        await check_message(expected_messages=["Finished sending information to test (0 chunks sent).",
                                               "Error sending information to test: Error 1000 - Wazuh Internal Error"])

    # Test successful workflow for 2 chunks
    sync_worker = worker.RetrieveAndSendToMaster(worker=worker_handler, destination_daemon='test', logger=logger,
                                                 msg_format='test_format {payload}',
                                                 data_retriever=lambda: ['test1', 'test2'])
    with patch('wazuh.core.cluster.local_client.LocalClient.execute', return_value='ok') as mock_lc:
        await check_message(expected_messages=["Finished sending information to test (2 chunks sent).",
                                               "Master's test response: ok.",
                                               "Master's test response: ok.",
                                               "Starting to send information to test."])
        calls = [call(command=b'sendasync', data=b'{"daemon_name": "test", "message": "test_format test1"}',
                      wait_for_complete=False),
                 call(command=b'sendasync', data=b'{"daemon_name": "test", "message": "test_format test2"}',
                      wait_for_complete=False)]
        mock_lc.assert_has_calls(calls)

    # Test unsuccessful workflow for 1 chunks
    sync_worker = worker.RetrieveAndSendToMaster(worker=worker_handler, destination_daemon='test', logger=logger,
                                                 expected_res='test_res', n_retries=1, data_retriever=lambda: ['test1'],
                                                 cmd=b'sync_a_m_w')
    with patch('wazuh.core.cluster.local_client.LocalClient.execute', return_value='ok') as mock_lc:
        with patch('wazuh.core.cluster.common.Handler.send_request', return_value='ok'):
            await check_message(expected_messages=["Finished sending information to test (0 chunks sent).",
                                                   "Master response for b'sync_a_m_w_e' command: ok",
                                                   "Master's test response: ok.",
                                                   "Error sending chunk to master's test. Response does not start with"
                                                   " test_res. Retrying... 0.",
                                                   "Master's test response: ok.",
                                                   "Starting to send information to test.",
                                                   "Master response for b'sync_a_m_w_s' command: ok",
                                                   "Obtained 1 chunks of data to be sent.",
                                                   "Obtaining data to be sent to master's test."])
            calls = [
                call(command=b'sendasync', data=b'{"daemon_name": "test", "message": "test1"}', wait_for_complete=False),
                call(command=b'sendasync', data=b'{"daemon_name": "test", "message": "test1"}', wait_for_complete=False)
            ]
            mock_lc.assert_has_calls(calls)


def test_WorkerHandler():
    worker_handler = get_worker_handler()
    with patch('wazuh.core.cluster.client.AbstractClient.connection_result', side_effect=None):
        with patch('os.path.exists', return_value=False):
            with patch('wazuh.core.cluster.worker.utils.mkdir_with_mode', side_effect=None):
                worker_handler.connected = True
                worker_handler.connection_result(future_result=None)

    assert worker_handler.process_request(command=b'sync_m_c_ok', data=b'Testing') == (b'ok', b'Thanks')

    with patch('wazuh.core.cluster.common.WazuhCommon.setup_receive_file', side_effect=(b'ok', b'Thanks')):
        assert worker_handler.process_request(command=b'sync_m_c', data=b'Testing') == b'ok'

    with patch('wazuh.core.cluster.common.WazuhCommon.end_receiving_file',
               side_effect=(b'ok', b'File correctly received')):
        assert worker_handler.process_request(command=b'sync_m_c_e', data=b'Testing First') == b'ok'

    with patch('wazuh.core.cluster.common.WazuhCommon.error_receiving_file',
               side_effect=(b'ok', b'File correctly received')):
        assert worker_handler.process_request(command=b'sync_m_c_r', data=b'Testing') == b'ok'

    with patch('asyncio.create_task', side_effect=None):
        assert worker_handler.process_request(command=b'dapi_res', data=b'Testing') == \
               (b'ok', b'Response forwarded to worker')

        # worker.py:162 local_server is not a member of AbstractClientManager
        # assert worker_handler.process_request(command=b'dapi_err', data=b'Testing Error') == \
        #        (b'ok', b'DAPI error forwarded to worker')

        # worker.py:167 dapi is not a member of AbstractClientManager
        # assert worker_handler.process_request(command=b'dapi', data=b'Testing Error') == \
        #        (b'ok', b'Added request to API requests queue')

    assert worker_handler.process_request(command=b'no_exists', data=b'Testing') == (
        b'err', b"unknown command 'b'no_exists''")

    assert worker_handler.get_manager()


@pytest.mark.asyncio
async def test_WorkerHandler_sync_integrity():
    worker_handler = get_worker_handler()
    worker_handler.cluster_items = {'intervals': {'worker': {'sync_integrity': 1}}}
    worker_handler.connected = True
    with patch('wazuh.core.cluster.common.Handler.send_request', new=AsyncMock(return_value=b'True')):
        with patch('asyncio.sleep', side_effect=TimeoutError()):
            with pytest.raises(TimeoutError):
                await worker_handler.sync_integrity()

    with patch('time.time', side_effect=WazuhException(1001)):
        with patch('asyncio.sleep', side_effect=TimeoutError()):
            with pytest.raises(WazuhException, match=r'.* 1001 .*'):
                await worker_handler.sync_integrity()

    with patch('time.time', side_effect=TimeoutError()):
        with patch('asyncio.sleep', side_effect=TimeoutError()):
            with pytest.raises(TimeoutError):
                await worker_handler.sync_integrity()
