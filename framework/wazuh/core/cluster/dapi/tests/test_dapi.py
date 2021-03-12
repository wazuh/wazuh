# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import logging
import os
import sys
from asyncio import TimeoutError
from unittest.mock import patch, MagicMock

import pytest
from connexion import ProblemException

from wazuh.core import common

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../../../../../api'))

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']

        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.core.cluster.dapi.dapi import DistributedAPI, APIRequestQueue
        from wazuh.core.manager import get_manager_status
        from wazuh.core.results import WazuhResult, AffectedItemsWazuhResult
        from wazuh import agent, cluster, ciscat, manager, WazuhError, WazuhInternalError
        from wazuh.core.exception import WazuhClusterError
        from api.util import raise_if_exc

logger = logging.getLogger('wazuh')
loop = asyncio.get_event_loop()


def AsyncMock(*args, **kwargs):
    m = MagicMock(*args, **kwargs)

    async def mock_coro(*args, **kwargs):
        return m(*args, **kwargs)

    mock_coro.mock = m
    return mock_coro


def raise_if_exc_routine(dapi_kwargs, expected_error=None):
    dapi = DistributedAPI(**dapi_kwargs)
    try:
        raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    except ProblemException as e:
        if expected_error:
            assert e.ext['code'] == expected_error
        else:
            assert False, f'Unexpected exception: {e.ext}'


@pytest.mark.parametrize('kwargs', [
    {'f_kwargs': {'select': ['id']}, 'rbac_permissions': {'mode': 'black'}, 'nodes': ['worker1'],
     'basic_services': ('wazuh-modulesd', 'wazuh-db'), 'request_type': 'local_master'},
    {'request_type': 'local_master'}
])
@patch('wazuh.core.cluster.dapi.dapi.common.install_type', return_value='local')
def test_DistributedAPI(install_type_mock, kwargs):
    """Test constructor from DistributedAPI class.

    Parameters
    ----------
    kwargs : dict
        Dict with some kwargs to pass when instancing the class.
    """
    dapi = DistributedAPI(f=agent.get_agents_summary_status, logger=logger, **kwargs)
    assert isinstance(dapi, DistributedAPI)


@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.execute_local_request',
       new=AsyncMock(return_value=WazuhResult({'result': 'local'})))
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.forward_request',
       new=AsyncMock(return_value=WazuhResult({'result': 'forward'})))
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.execute_remote_request',
       new=AsyncMock(return_value=WazuhResult({'result': 'remote'})))
@pytest.mark.parametrize('api_request, request_type, node, expected', [
    (agent.get_agents_summary_status, 'local_master', 'master', 'local'),
    (agent.restart_agents, 'distributed_master', 'master', 'forward'),
    (cluster.get_node_wrapper, 'local_any', 'worker', 'local'),
    (ciscat.get_ciscat_results, 'distributed_master', 'worker', 'remote')
])
@patch('wazuh.core.cluster.dapi.dapi.wazuh.core.cluster.cluster.check_cluster_status', return_value=False)
def test_DistributedAPI_distribute_function(cluster_status_mock, api_request, request_type, node, expected):
    """Test distribute_function functionality with different test cases.

    Parameters
    ----------
    api_request : callable
        Function to be executed
    request_type : str
        Request type (local_master, distributed_master, local_any)
    node : str
        Node type (Master and Workers)
    expected : str
        Expected result
    """
    with patch('wazuh.core.cluster.cluster.get_node', return_value={'type': node}):
        dapi = DistributedAPI(f=api_request, logger=logger, request_type=request_type)
        data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
        assert data.render()['result'] == expected


@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.execute_local_request',
       new=AsyncMock(return_value=WazuhResult({'result': 'local'})))
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.get_solver_node',
       new=AsyncMock(return_value=WazuhResult({'unknown': ['001', '002']})))
@pytest.mark.parametrize('api_request, request_type, node, expected', [
    (agent.restart_agents, 'distributed_master', 'master', 'local')
])
@patch('wazuh.core.cluster.dapi.dapi.wazuh.core.cluster.cluster.check_cluster_status', return_value=False)
def test_DistributedAPI_distribute_function_mock_solver(cluster_status_mock, api_request, request_type, node, expected):
    """Test distribute_function functionality with unknown node.

    Parameters
    ----------
    api_request : callable
        Function to be executed
    request_type : str
        Request type (local_master, distributed_master, local_any)
    node : str
        Node type (Master and Workers)
    expected : str
        Expected result
    """
    with patch('wazuh.core.cluster.cluster.get_node', return_value={'type': node, 'node': 'master'}):
        dapi = DistributedAPI(f=api_request, logger=logger, request_type=request_type, from_cluster=False)
        data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
        assert data.render()['result'] == expected


def test_DistributedAPI_distribute_function_exception():
    """Test distribute_function when an exception is raised.
    """
    dapi_kwargs = {'f': manager.restart, 'logger': logger}
    raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=1017)


@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.execute_local_request',
       new=AsyncMock(return_value='{wrong\': json}'))
def test_DistributedAPI_invalid_json():
    """Check the behaviour of DistributedAPI when an invalid JSON is received."""
    dapi_kwargs = {'f': agent.get_agents_summary_status, 'logger': logger}
    assert raise_if_exc_routine(dapi_kwargs=dapi_kwargs) is None


def test_DistributedAPI_local_request_errors():
    """Check the behaviour when the local_request function raised an error."""
    with patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.execute_local_request',
               new=AsyncMock(side_effect=WazuhInternalError(1001))):
        dapi_kwargs = {'f': agent.get_agents_summary_status, 'logger': logger}
        raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=1001)

        dapi_kwargs['debug'] = True
        dapi = DistributedAPI(f=agent.get_agents_summary_status, logger=logger, debug=True)
        try:
            raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
        except WazuhInternalError as e:
            assert e.code == 1001

    with patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.execute_local_request',
               new=AsyncMock(side_effect=KeyError('Testing'))):
        dapi_kwargs = {'f': agent.get_agents_summary_status, 'logger': logger}
        raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=1000)  # Specify KeyError

        dapi = DistributedAPI(f=agent.get_agents_summary_status, logger=logger, debug=True)
        try:
            raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
        except KeyError as e:
            assert 'KeyError' in repr(e)


@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.check_wazuh_status', side_effect=None)
@patch('asyncio.wait_for', new=AsyncMock(return_value='Testing'))
def test_DistributedAPI_local_request(mock_local_request):
    """Test `local_request` method from class DistributedAPI and check the behaviour when an error raise."""
    dapi_kwargs = {'f': manager.status, 'logger': logger}
    raise_if_exc_routine(dapi_kwargs=dapi_kwargs)

    dapi_kwargs = {'f': cluster.get_nodes_info, 'logger': logger, 'local_client_arg': 'lc'}
    raise_if_exc_routine(dapi_kwargs=dapi_kwargs)

    dapi_kwargs['is_async'] = True
    raise_if_exc_routine(dapi_kwargs=dapi_kwargs)

    with patch('asyncio.wait_for', new=AsyncMock(side_effect=TimeoutError('Testing'))):
        dapi = DistributedAPI(f=manager.status, logger=logger)
        try:
            raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
        except ProblemException as e:
            assert e.ext['dapi_errors'][list(e.ext['dapi_errors'].keys())[0]]['error'] == \
                   'Timeout executing API request'

    with patch('asyncio.wait_for', new=AsyncMock(side_effect=WazuhError(1001))):
        dapi_kwargs = {'f': manager.status, 'logger': logger}
        raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=1001)

        dapi_kwargs['debug'] = True
        raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=1001)

    with patch('asyncio.wait_for', new=AsyncMock(side_effect=WazuhInternalError(1001))):
        dapi_kwargs = {'f': manager.status, 'logger': logger}
        raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=1001)

        dapi = DistributedAPI(f=manager.status, logger=logger, debug=True)
        try:
            raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
        except WazuhInternalError as e:
            assert e.code == 1001

    with patch('asyncio.wait_for', new=AsyncMock(side_effect=KeyError('Testing'))):
        dapi_kwargs = {'f': manager.status, 'logger': logger}
        raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=1000)

        dapi = DistributedAPI(f=manager.status, logger=logger, debug=True)
        try:
            raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
        except Exception as e:
            assert type(e) == KeyError


@patch('wazuh.core.cluster.cluster.check_cluster_status', return_value=False)
@patch('wazuh.core.cluster.local_client.LocalClient.execute', new=AsyncMock(return_value='{"Testing": 1}'))
def test_DistributedAPI_remote_request(mock_cluster_status):
    """Test `execute_remote_request` method from class DistributedAPI."""
    dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'remote'}
    raise_if_exc_routine(dapi_kwargs=dapi_kwargs)


@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.execute_local_request',
       new=AsyncMock(side_effect=WazuhInternalError(1001)))
def test_DistributedAPI_logger():
    """Test custom logger inside DistributedAPI class."""
    new_logger = logging.getLogger('dapi_test')
    fh = logging.FileHandler('/tmp/dapi_test.log')
    fh.setLevel(logging.DEBUG)
    new_logger.addHandler(fh)
    dapi_kwargs = {'f': agent.get_agents_summary_status, 'logger': new_logger}
    raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=1001)


@patch('wazuh.core.cluster.cluster.check_cluster_status', return_value=False)
@patch('wazuh.core.cluster.local_client.LocalClient.send_file', new=AsyncMock(return_value='{"Testing": 1}'))
@patch('wazuh.core.cluster.local_client.LocalClient.execute', new=AsyncMock(return_value='{"Testing": 1}'))
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.get_solver_node',
       new=AsyncMock(return_value=WazuhResult({'testing': ['001', '002']})))
def test_DistributedAPI_tmp_file(mock_cluster_status):
    """Test the behaviour when processing temporal files to be send. Master node and unknown node."""
    open('/tmp/dapi_file.txt', 'a').close()
    with patch('wazuh.core.cluster.cluster.get_node', return_value={'type': 'master', 'node': 'unknown'}):
        with patch('wazuh.core.cluster.dapi.dapi.get_node_wrapper',
                   return_value=AffectedItemsWazuhResult(affected_items=[{'type': 'master', 'node': 'unknown'}])):
            dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'distributed_master',
                           'f_kwargs': {'tmp_file': '/tmp/dapi_file.txt'}}
            raise_if_exc_routine(dapi_kwargs=dapi_kwargs)

    open('/tmp/dapi_file.txt', 'a').close()
    with patch('wazuh.core.cluster.cluster.get_node', return_value={'type': 'unk', 'node': 'master'}):
        raise_if_exc_routine(dapi_kwargs=dapi_kwargs)


@patch('wazuh.core.cluster.cluster.check_cluster_status', return_value=False)
@patch('wazuh.core.cluster.local_client.LocalClient.send_file', new=AsyncMock(return_value='{"Testing": 1}'))
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.get_solver_node',
       new=AsyncMock(return_value=WazuhResult({'testing': ['001', '002']})))
def test_DistributedAPI_tmp_file_cluster_error(mock_cluster_status):
    """Test the behaviour when an error raises with temporal files function."""
    open('/tmp/dapi_file.txt', 'a').close()
    with patch('wazuh.core.cluster.cluster.get_node', return_value={'type': 'master', 'node': 'unknown'}):
        with patch('wazuh.core.cluster.dapi.dapi.get_node_wrapper',
                   return_value=AffectedItemsWazuhResult(affected_items=[{'type': 'master', 'node': 'unknown'}])):
            with patch('wazuh.core.cluster.local_client.LocalClient.execute',
                       new=AsyncMock(side_effect=WazuhClusterError(3022))):
                dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'distributed_master',
                               'f_kwargs': {'tmp_file': '/tmp/dapi_file.txt'}}
                raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=3022)

            open('/tmp/dapi_file.txt', 'a').close()
            with patch('wazuh.core.cluster.local_client.LocalClient.execute',
                       new=AsyncMock(side_effect=WazuhClusterError(1000))):
                dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'distributed_master',
                               'f_kwargs': {'tmp_file': '/tmp/dapi_file.txt'}}
                raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=1000)


def filter_node_mock(filter_node=None, *args, **kwargs):
    if 'filter_node' in kwargs:
        del kwargs['filter_node']

    cluster.get_nodes_info(*args, filter_node=filter_node, **kwargs)


@patch('wazuh.core.cluster.cluster.check_cluster_status', return_value=False)
@patch('wazuh.core.cluster.local_client.LocalClient.execute',
       new=AsyncMock(return_value='{"items": [{"name": "master"}], "totalItems": 1}'))
@patch('wazuh.agent.Agent.get_agents_overview', return_value={'items': [{'id': '001', 'node_name': 'master'},
                                                                        {'id': '002', 'node_name': 'master'}]})
def test_DistributedAPI_get_solver_node(mock_cluster_status, mock_agents_overview):
    """Test `get_solver_node` function."""
    nodes_info_result = AffectedItemsWazuhResult()
    nodes_info_result.affected_items.append({'name': 'master'})
    common.cluster_nodes.set(['master'])

    with patch('wazuh.core.cluster.dapi.dapi.get_nodes_info', new=AsyncMock(return_value=nodes_info_result)):
        with patch('wazuh.core.cluster.cluster.get_node', return_value={'type': 'master', 'node': 'unknown'}):
            dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'distributed_master',
                           'f_kwargs': {'agent_list': ['001', '002']}, 'nodes': ['master']}
            raise_if_exc_routine(dapi_kwargs=dapi_kwargs)

            dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'distributed_master',
                           'f_kwargs': {'node_id': 'master'}, 'nodes': ['master']}
            raise_if_exc_routine(dapi_kwargs=dapi_kwargs)

            expected = AffectedItemsWazuhResult()
            expected.affected_items = [{'id': '001', 'node_name': 'master'}]
            with patch('wazuh.agent.get_agents_in_group', return_value=expected):
                dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'distributed_master',
                               'f_kwargs': {'group_id': 'default'}, 'nodes': ['master']}
                raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=1755)

            expected.affected_items = []
            with patch('wazuh.agent.get_agents_in_group', return_value=expected):
                dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'distributed_master',
                               'f_kwargs': {'group_id': 'noexist'}, 'nodes': ['master']}
                raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=1755)

            dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'distributed_master',
                           'f_kwargs': {'node_list': '*'}, 'broadcasting': True, 'nodes': ['master']}
            raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=1755)


@pytest.mark.parametrize('api_request', [
    agent.get_agents_summary_status,
    wazuh.core.manager.status
])
@patch('wazuh.core.manager.get_manager_status', return_value={process: 'running' for process in get_manager_status()})
def test_DistributedAPI_check_wazuh_status(status_mock, api_request):
    """Test `check_wazuh_status` method from class DistributedAPI."""
    dapi = DistributedAPI(f=api_request, logger=logger)
    data = dapi.check_wazuh_status()
    assert data is None


@pytest.mark.parametrize('status_value', [
    'failed',
    'restarting',
    'stopped'
])
@patch('wazuh.core.cluster.cluster.get_node', return_value={'node': 'random_node'})
def test_DistributedAPI_check_wazuh_status_exception(node_info_mock, status_value):
    """Test exceptions from `check_wazuh_status` method from class DistributedAPI."""
    statuses = {process: status_value for process in sorted(get_manager_status())}
    with patch('wazuh.core.manager.get_manager_status',
               return_value=statuses):
        dapi = DistributedAPI(f=agent.get_agents_summary_status, logger=logger)
        try:
            dapi.check_wazuh_status()
        except WazuhError as e:
            assert e.code == 1017
            assert statuses
            assert e._extra_message['node_name'] == 'random_node'
            extra_message = ', '.join([f'{key}->{statuses[key]}' for key in dapi.basic_services if key in statuses])
            assert e._extra_message['not_ready_daemons'] == extra_message


def test_APIRequestQueue():
    """Test `APIRequestQueue` constructor."""
    server = DistributedAPI(f=agent.get_agents_summary_status, logger=logger)
    api_request_queue = APIRequestQueue(server=server)
    api_request_queue.add_request(b'testing')
    assert api_request_queue.server == server
