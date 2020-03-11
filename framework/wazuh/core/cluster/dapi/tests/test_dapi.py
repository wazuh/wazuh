# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import os
import sys
from unittest.mock import patch, MagicMock
from logging import getLogger

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../../../../../api'))

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']

        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.core.cluster.dapi.dapi import DistributedAPI
        from wazuh.core.manager import status as manager_status
        from wazuh.results import WazuhResult
        from wazuh import agent, cluster, ciscat
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
