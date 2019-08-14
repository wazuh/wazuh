# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch, mock_open
import pytest
from wazuh.cluster import worker
import logging


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
@patch('wazuh.cluster.worker.WorkerHandler.remove_bulk_agents')
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
@patch('wazuh.cluster.worker.WazuhDBConnection')
@patch('shutil.rmtree')
@patch('os.remove')
@patch('glob.iglob')
@patch('wazuh.agent.Agent.get_agents_overview')
@patch('wazuh.cluster.worker.Connection')
@patch('os.path.isdir')
def test_remove_bulk_agents(isdir_mock, connection_mock, agents_mock, glob_mock, remove_mock, rmtree_mock, wdb_mock, agents_to_remove):
    """
    Tests WorkerHandler.remove_bulk_agents function.
    """
    agents_mock.return_value = {'totalItems': len(agents_to_remove),
                                'items': [{'id': a_id, 'ip': '0.0.0.0', 'name': 'test'} for a_id in agents_to_remove]}
    files_to_remove = ['/var/ossec/queue/agent-info/{name}-{ip}', '/var/ossec/queue/rootcheck/({name}) {ip}->rootcheck',
                       '/var/ossec/queue/diff/{name}', '/var/ossec/queue/agent-groups/{id}',
                       '/var/ossec/queue/rids/{id}', '/var/ossec/var/db/agents/{name}-{id}.db', 'global.db']
    glob_mock.side_effect = [[f.format(id=a, ip='0.0.0.0', name='test') for a in agents_to_remove] for f in files_to_remove]
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
