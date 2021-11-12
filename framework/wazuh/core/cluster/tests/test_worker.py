# Copyright (C) 2015-2021, Wazuh Inc.
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

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
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
async def test_SyncTask(create_log, caplog):
    async def check_message(mock, expected_message, method, *args, **kwargs):
        with patch('wazuh.core.cluster.common.Handler.send_request', new=AsyncMock(return_value=mock)):
            with caplog.at_level(logging.DEBUG):
                await method(*args, **kwargs)
                assert expected_message in caplog.records[-1].message

    worker_handler = get_worker_handler()
    sync_task = worker.SyncTask(cmd=b'testing', logger=logger, worker=worker_handler)

    await check_message(mock=KeyError(1), expected_message=f"Error asking for permission: 1",
                        method=sync_task.request_permission)
    await check_message(mock=b'False', expected_message="Master didn't grant permission to start",
                        method=sync_task.request_permission)
    await check_message(mock=b'True', expected_message="Permission to synchronize granted.",
                        method=sync_task.request_permission)


@pytest.mark.asyncio
async def test_SyncWorker(create_log, caplog):
    worker_handler = get_worker_handler()
    sync_worker = worker.SyncFiles(cmd=b'testing', logger=logger, worker=worker_handler)

    error = WazuhException(1001)
    with patch('wazuh.core.cluster.common.Handler.send_request', new=AsyncMock(return_value=b'True')):
        with patch('wazuh.core.cluster.common.Handler.send_file', new=AsyncMock(side_effect=error)):
            await sync_worker.sync(files_to_sync={'files': ['testing']}, files_metadata={'testing': '0'})
            assert 'Error sending zip file' in caplog.records[-1].message

    error = KeyError(1)
    with patch('wazuh.core.cluster.common.Handler.send_request', new=AsyncMock(return_value=b'True')):
        with patch('wazuh.core.cluster.common.Handler.send_file', new=AsyncMock(side_effect=error)):
            await sync_worker.sync(files_to_sync={'files': ['testing']}, files_metadata={'testing': '0'})
            assert 'Error sending zip file' in caplog.records[-1].message


@pytest.mark.asyncio
async def test_SyncWazuhdb(create_log, caplog):
    async def check_message(mock, expected_messages, *args, **kwargs):
        with patch('wazuh.core.cluster.common.Handler.send_request', new=AsyncMock(return_value=mock)):
            with caplog.at_level(logging.DEBUG):
                await sync_worker.sync(*args, **kwargs)
                for i, expected_message in enumerate(expected_messages):
                    assert expected_message in caplog.records[-(i + 1)].message

    worker_handler = get_worker_handler()
    sync_worker = worker.SyncWazuhdb(worker=worker_handler, logger=logger, cmd=b'syn_a_w_m', data_retriever=MagicMock(),
                                     get_data_command='test-get', set_data_command='test-set')

    sync_worker = worker.SyncWazuhdb(worker=worker_handler, logger=logger, cmd=b'syn_a_w_m',
                                     get_data_command='test-get', set_data_command='test-set',
                                     data_retriever=lambda x: [])
    await check_message(mock=b'True', expected_messages=["(0 chunks sent)",
                                                         "Obtained 0 chunks of data in"], start_time=123.456)

    sync_worker = worker.SyncWazuhdb(worker=worker_handler, logger=logger, cmd=b'syn_a_w_m',
                                     get_data_command='test-get', set_data_command='test-set',
                                     data_retriever=lambda x: ['test0', 'test1'])
    await check_message(mock=b'True', expected_messages=["All chunks sent.",
                                                         "Obtained 2 chunks of data in"], start_time=123.456)

    sync_worker = worker.SyncWazuhdb(worker=worker_handler, logger=logger, cmd=b'syn_a_w_m',
                                     get_data_command='test-get', set_data_command='test-set',
                                     data_retriever=lambda x: exec('raise(WazuhException(1000))'))
    await check_message(mock=b'True', expected_messages=["Error obtaining data from wazuh-db"], start_time=123.456)


def test_WorkerHandler():
    worker_handler = get_worker_handler()
    with patch('wazuh.core.cluster.client.AbstractClient.connection_result', side_effect=None):
        with patch('os.path.exists', return_value=False):
            with patch('wazuh.core.cluster.worker.utils.mkdir_with_mode', side_effect=None):
                worker_handler.connected = True
                worker_handler.connection_result(future_result=None)

    assert worker_handler.process_request(command=b'syn_m_c_ok', data=b'Testing') == (b'ok', b'Thanks')

    with patch('wazuh.core.cluster.common.WazuhCommon.setup_receive_file', side_effect=(b'ok', b'Thanks')):
        assert worker_handler.process_request(command=b'syn_m_c', data=b'Testing') == b'ok'

    with patch('wazuh.core.cluster.common.WazuhCommon.end_receiving_file',
               side_effect=(b'ok', b'File correctly received')):
        assert worker_handler.process_request(command=b'syn_m_c_e', data=b'Testing First') == b'ok'

    with patch('wazuh.core.cluster.common.WazuhCommon.error_receiving_file',
               side_effect=(b'ok', b'File correctly received')):
        assert worker_handler.process_request(command=b'syn_m_c_r', data=b'Testing') == b'ok'

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
