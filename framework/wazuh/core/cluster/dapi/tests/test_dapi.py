# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import os
import sys
from logging import getLogger
from unittest.mock import patch, MagicMock

import pytest
from connexion import ProblemException

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../../../../../api'))

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']

        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.core.cluster.dapi.dapi import DistributedAPI
        from wazuh.core.manager import get_manager_status
        from wazuh.results import WazuhResult
        from wazuh import agent, cluster, ciscat, manager, WazuhError
        from api.util import raise_if_exc

logger = getLogger('wazuh')
loop = asyncio.get_event_loop()


def AsyncMock(*args, **kwargs):
    m = MagicMock(*args, **kwargs)

    async def mock_coro(*args, **kwargs):
        return m(*args, **kwargs)

    mock_coro.mock = m
    return mock_coro


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
    with patch('wazuh.core.cluster.cluster.get_node', return_value={'type': node}):
        dapi = DistributedAPI(f=api_request, logger=logger, request_type=request_type)
        data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
        assert data.render()['result'] == expected


@pytest.mark.parametrize('api_request, cluster_req, error_code, message', [
    (manager.restart, True, 3013, None)
])
def test_DistributedAPI_distribute_function_exception(api_request, cluster_req, error_code, message):
    dapi = DistributedAPI(f=api_request, logger=logger, cluster_required=cluster_req)
    try:
        raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    except ProblemException as e:
        assert e.ext['code'] == error_code


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
