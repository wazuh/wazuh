# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import json
import logging
import os
import sys
from asyncio import TimeoutError
from unittest.mock import call, MagicMock, patch

import pytest
from connexion import ProblemException
from sqlalchemy.exc import OperationalError
from sqlite3 import OperationalError as SQLiteOperationalError, DatabaseError, Error

from wazuh.core import common

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../../../../../api'))

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']

        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.core.cluster.dapi.dapi import DistributedAPI, APIRequestQueue, SendSyncRequestQueue
        from wazuh.core.manager import get_manager_status
        from wazuh.core.results import WazuhResult, AffectedItemsWazuhResult
        from wazuh import agent, cluster, ciscat, manager, WazuhError, WazuhInternalError
        from wazuh.core.exception import WazuhClusterError
        from api.util import raise_if_exc
        from wazuh.core.cluster import local_client

logger = logging.getLogger('wazuh')
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

DEFAULT_REQUEST_TIMEOUT = 10


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
        if expected_error:
            assert False, f'Expected exception not generated: {expected_error}'
    except ProblemException as e:
        if expected_error:
            assert e.ext['code'] == expected_error
        else:
            assert False, f'Unexpected exception: {e.ext}'


class TestingLoggerParent:
    """Class used to create the parent attribute of TestingLogger objects."""
    __test__ = False

    def __init__(self):
        self.handlers = []


class TestingLogger:
    """Class used to create custom Logger objects for testing purposes."""
    __test__ = False
    
    def __init__(self, logger_name):
        self.name = logger_name
        self.handlers = []
        self.parent = TestingLoggerParent()

    def error(self, message):
        pass

    def debug(self, message):
        pass

    def debug2(self, message):
        pass


@pytest.mark.parametrize('kwargs', [
    {'f_kwargs': {'select': ['id']}, 'rbac_permissions': {'mode': 'black'}, 'nodes': ['worker1'],
     'basic_services': ('wazuh-modulesd', 'wazuh-db'), 'request_type': 'local_master'},
    {'request_type': 'local_master'},
    {'api_timeout': 15},
    {'api_timeout': 5}
])
def test_DistributedAPI(kwargs):
    """Test constructor from DistributedAPI class.

    Parameters
    ----------
    kwargs : dict
        Dict with some kwargs to pass when instancing the class.
    """
    dapi = DistributedAPI(f=agent.get_agents_summary_status, logger=logger, **kwargs)
    assert isinstance(dapi, DistributedAPI)
    assert dapi.api_request_timeout == max(kwargs.get('api_timeout', 0), DEFAULT_REQUEST_TIMEOUT)


def test_DistributedAPI_debug_log():
    """Check that error messages are correctly sent to the logger in the DistributedAPI class."""
    logger_ = TestingLogger(logger_name="wazuh-api")
    message = "Testing debug2"
    with patch.object(logger_, "debug2") as debug2_mock:
        dapi = DistributedAPI(f=agent.get_agents_summary_status, logger=logger_)
        dapi.debug_log(message)
        debug2_mock.assert_called_once_with(message)

    logger_ = TestingLogger(logger_name="wazuh")
    message = "Testing debug"
    with patch.object(logger_, "debug") as debug_mock:
        dapi = DistributedAPI(f=agent.get_agents_summary_status, logger=logger_)
        dapi.debug_log(message)
        debug_mock.assert_called_once_with(message)


@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.execute_local_request',
       new=AsyncMock(return_value=WazuhResult({'result': 'local'})))
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.forward_request',
       new=AsyncMock(return_value=WazuhResult({'result': 'forward'})))
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.execute_remote_request',
       new=AsyncMock(return_value=WazuhResult({'result': 'remote'})))
@pytest.mark.parametrize('api_request, request_type, node, expected, cluster_enabled, f_kwargs', [
    (agent.get_agents_summary_status, 'local_master', 'master', 'local', True, None),
    (agent.restart_agents, 'distributed_master', 'master', 'forward', True, None),
    (cluster.get_node_wrapper, 'local_any', 'worker', 'local', True, 'token_nbf_time'),
    (ciscat.get_ciscat_results, 'distributed_master', 'worker', 'remote', True, None),
    (manager.status, 'local_master', 'worker', 'local', False, {'password': 'testing'}),
    (manager.status, 'local_master', 'worker', 'local', False, None)
])
def test_DistributedAPI_distribute_function(api_request, request_type, node, expected, cluster_enabled, f_kwargs):
    """Test distribute_function functionality with different test cases.

    Parameters
    ----------
    api_request : callable
        Function to be executed.
    request_type : str
        Request type (local_master, distributed_master, local_any).
    node : str
        Node type (Master and Workers).
    expected : str
        Expected result.
    cluster_enabled : bool
        Indicates whether cluster is enabled or not.
    """

    # Mock check_cluster_status and get_node
    with patch('wazuh.core.cluster.dapi.dapi.check_cluster_status', return_value=cluster_enabled):
        with patch('wazuh.core.cluster.dapi.dapi.node_info', {'type': node}):
            dapi = DistributedAPI(f=api_request, logger=logger, request_type=request_type, f_kwargs=f_kwargs)
            data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
            assert data.render()['result'] == expected


@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.execute_local_request',
       new=AsyncMock(return_value=WazuhResult({'result': 'local'})))
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.get_solver_node',
       new=AsyncMock(return_value=WazuhResult({'unknown': ['001', '002']})))
@pytest.mark.parametrize('api_request, request_type, node, expected', [
    (agent.restart_agents, 'distributed_master', 'master', 'local')
])
def test_DistributedAPI_distribute_function_mock_solver(api_request, request_type, node, expected):
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
    """Test distribute_function when an exception is raised."""

    class NodeWrapper:
        def __init__(self):
            self.affected_items = []
            self.failed_items = {Exception("test_get_error_info"): "abc"}

    dapi_kwargs = {'f': manager.restart, 'logger': logger}
    raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=1017)

    logger_ = logging.getLogger("wazuh")
    with patch("wazuh.core.cluster.dapi.dapi.get_node_wrapper", side_effect=WazuhError(4000)):
        dapi = DistributedAPI(f=agent.get_agents_summary_status, logger=logger_)
        get_error_result = dapi.get_error_info(Exception("testing"))
        assert 'unknown-node' in get_error_result
        assert get_error_result['unknown-node']['error'] == 'Wazuh Internal Error. See log for more detail'

    with patch("wazuh.core.cluster.dapi.dapi.get_node_wrapper", side_effect=WazuhError(4001)):
        dapi = DistributedAPI(f=agent.get_agents_summary_status, logger=logger_)
        with pytest.raises(WazuhError, match='.* 4001 .*'):
            dapi.get_error_info(Exception("testing"))

    with patch("wazuh.core.cluster.dapi.dapi.get_node_wrapper", return_value=NodeWrapper()):
        dapi = DistributedAPI(f=agent.get_agents_summary_status, logger=logger_)
        with pytest.raises(Exception, match='.*test_get_error_info.*'):
            dapi.get_error_info(Exception("testing"))


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

    # Test execute_local_request when the dapi function (dapi.f) raises a JSONDecodeError
    with patch('wazuh.cluster.get_nodes_info', side_effect=json.decoder.JSONDecodeError('test', 'test', 1)):
        with patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.check_wazuh_status'):
            dapi_kwargs = {'f': cluster.get_nodes_info, 'logger': logger, 'is_async': True}
            raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=3036)


@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.check_wazuh_status', side_effect=None)
@patch('asyncio.wait_for', new=AsyncMock(return_value='Testing'))
def test_DistributedAPI_local_request(mock_local_request):
    """Test `local_request` method from class DistributedAPI and check the behaviour when an error raises."""
    dapi_kwargs = {'f': manager.status, 'logger': logger}
    raise_if_exc_routine(dapi_kwargs=dapi_kwargs)

    dapi_kwargs = {'f': cluster.get_nodes_info, 'logger': logger, 'local_client_arg': 'lc'}
    raise_if_exc_routine(dapi_kwargs=dapi_kwargs)

    dapi_kwargs['is_async'] = True
    raise_if_exc_routine(dapi_kwargs=dapi_kwargs)

    with patch('asyncio.wait_for', new=AsyncMock(side_effect=TimeoutError('Testing'))):
        dapi = DistributedAPI(f=manager.status, logger=logger, f_kwargs={'agent_list': '*'})
        try:
            raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
        except ProblemException as e:
            assert 'agent_list' not in dapi.f_kwargs
            assert e.ext['dapi_errors'][list(e.ext['dapi_errors'].keys())[0]]['error'] == \
                   'Timeout executing API request'

    with patch('asyncio.wait_for', new=AsyncMock(side_effect=WazuhError(1001))):
        dapi_kwargs = {'f': manager.status, 'logger': logger}
        raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=1001)

        dapi_kwargs['debug'] = True
        raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=1001)

    with patch('asyncio.wait_for', new=AsyncMock(side_effect=asyncio.TimeoutError())):
        dapi_kwargs = {'f': manager.status, 'logger': logger}
        raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=3021)

    orig_message = 'database or disk is full'
    orig = SQLiteOperationalError(DatabaseError(Error(Exception(orig_message))))
    with patch('asyncio.wait_for', new=AsyncMock(side_effect=OperationalError(statement=None, params=[], orig=orig))):
        dapi_kwargs = {'f': manager.status, 'logger': logger}
        raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=2008)

        dapi = DistributedAPI(f=manager.status, logger=logger, debug=True)
        try:
            raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
        except WazuhInternalError as e:
            assert e.code == 2008
            assert str(e).endswith(orig_message)

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

    testing_logger = TestingLogger('test')
    exc_code = 3000
    cluster_exc = WazuhClusterError(exc_code)
    with patch('asyncio.wait_for', new=AsyncMock(side_effect=cluster_exc)):
        with patch.object(TestingLogger, "error") as logger_error_mock:
            # Test WazuhClusterError caught in execute_local_request and ProblemException raised
            dapi_kwargs = {'f': manager.status, 'logger': testing_logger}
            raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=exc_code)

            # Test WazuhClusterError is raised when using debug in execute_local_request and distribute_function
            dapi = DistributedAPI(f=manager.status, logger=testing_logger, debug=True)
            try:
                raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
            except WazuhClusterError as e:
                assert e.dapi_errors == dapi.get_error_info(e)

            # Test the logger `error` method was called for both distribute_function calls
            logger_error_mock.assert_has_calls([call(f"{cluster_exc.message}", exc_info=False),
                                                call(f"{cluster_exc.message}", exc_info=False)])


@patch("asyncio.get_running_loop")
def test_DistributedAPI_get_client(loop_mock):
    """Test get_client function from DistributedAPI."""

    class Node:
        def __init__(self):
            self.cluster_items = {"cluster_items": ["worker1", "worker2"]}

        def get_node(self):
            pass

    logger = logging.getLogger("test")
    dapi = DistributedAPI(f=agent.get_agents_summary_status, logger=logger)
    assert isinstance(dapi.get_client(), local_client.LocalClient)

    node = Node()
    dapi = DistributedAPI(f=agent.get_agents_summary_status, node=node, logger=logger)
    assert dapi.get_client()


@patch('wazuh.core.cluster.dapi.dapi.node_info', {'type': 'worker'})
@patch('wazuh.core.cluster.dapi.dapi.check_cluster_status', return_value=True)
@patch('wazuh.core.cluster.local_client.LocalClient.execute', return_value='invalid_json')
def test_DistributedAPI_remote_request_errors(mock_client_execute, mock_check_cluster_status):
    """Check the behaviour when the execute_remote_request function raised an error"""
    # Test execute_remote_request when it raises a JSONDecodeError
    dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'local_master'}
    raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=3036)


@patch('wazuh.core.cluster.local_client.LocalClient.execute', new=AsyncMock(return_value='{"Testing": 1}'))
def test_DistributedAPI_remote_request():
    """Test `execute_remote_request` method from class DistributedAPI."""
    dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'remote'}
    raise_if_exc_routine(dapi_kwargs=dapi_kwargs)


@patch('wazuh.core.cluster.cluster.get_node', return_value={'type': 'master', 'node': 'master-node'})
@patch('wazuh.core.cluster.dapi.dapi.check_cluster_status', return_value=True)
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.get_solver_node', return_value={'worker1': ['001', '002']})
@patch('wazuh.core.cluster.local_client.LocalClient.execute', return_value='invalid_json')
def test_DistributedAPI_forward_request_errors(mock_client_execute, mock_get_solver_node, mock_check_cluster_status,
                                               mock_get_node):
    """Check the behaviour when the forward_request function raised an error"""
    # Test forward_request when it raises a JSONDecodeError
    dapi_kwargs = {'f': agent.reconnect_agents, 'logger': logger, 'request_type': 'distributed_master'}
    raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=3036)


@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.execute_local_request',
       new=AsyncMock(side_effect=WazuhInternalError(1001)))
def test_DistributedAPI_logger():
    """Test custom logger inside DistributedAPI class."""
    log_file_path = '/tmp/dapi_test.log'
    try:
        new_logger = logging.getLogger('dapi_test')
        fh = logging.FileHandler(log_file_path)
        fh.setLevel(logging.DEBUG)
        new_logger.addHandler(fh)
        dapi_kwargs = {'f': agent.get_agents_summary_status, 'logger': new_logger}
        raise_if_exc_routine(dapi_kwargs=dapi_kwargs, expected_error=1001)
    finally:
        os.remove(log_file_path)


@patch('wazuh.core.cluster.local_client.LocalClient.send_file', new=AsyncMock(return_value='{"Testing": 1}'))
@patch('wazuh.core.cluster.local_client.LocalClient.execute', new=AsyncMock(return_value='{"Testing": 1}'))
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.get_solver_node',
       new=AsyncMock(return_value=WazuhResult({'testing': ['001', '002']})))
@patch('wazuh.core.cluster.dapi.dapi.check_cluster_status', return_value=True)
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


@patch('wazuh.core.cluster.local_client.LocalClient.send_file', new=AsyncMock(return_value='{"Testing": 1}'))
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.get_solver_node',
       new=AsyncMock(return_value=WazuhResult({'testing': ['001', '002']})))
@patch('wazuh.core.cluster.dapi.dapi.check_cluster_status', return_value=True)
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


@patch('wazuh.core.cluster.local_client.LocalClient.execute',
       new=AsyncMock(return_value='{"items": [{"name": "master"}], "totalItems": 1}'))
@patch('wazuh.agent.Agent.get_agents_overview', return_value={'items': [{'id': '001', 'node_name': 'master'},
                                                                        {'id': '002', 'node_name': 'master'},
                                                                        {'id': '003', 'node_name': 'unknown'}]})
@patch('wazuh.core.cluster.dapi.dapi.check_cluster_status', return_value=True)
def test_DistributedAPI_get_solver_node(mock_cluster_status, mock_agents_overview):
    """Test `get_solver_node` function."""
    nodes_info_result = AffectedItemsWazuhResult()
    nodes_info_result.affected_items.append({'name': 'master'})
    common.cluster_nodes.set(['master'])

    with patch('wazuh.core.cluster.dapi.dapi.get_nodes_info', new=AsyncMock(return_value=nodes_info_result)):
        with patch('wazuh.core.cluster.dapi.dapi.node_info', {'type': 'master', 'node': 'unknown'}):
            dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'distributed_master',
                           'f_kwargs': {'agent_list': ['001', '002']}, 'nodes': ['master']}
            raise_if_exc_routine(dapi_kwargs=dapi_kwargs)

            dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'distributed_master',
                           'f_kwargs': {'agent_list': ['003', '004']}, 'nodes': ['master']}
            raise_if_exc_routine(dapi_kwargs=dapi_kwargs)

            dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'distributed_master',
                           'f_kwargs': {'agent_list': ['003', '004'], 'node_id': 'worker1'}, 'nodes': ['master']}
            raise_if_exc_routine(dapi_kwargs=dapi_kwargs)

            dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'distributed_master',
                           'f_kwargs': {'agent_list': '*'}, 'nodes': ['master']}
            raise_if_exc_routine(dapi_kwargs=dapi_kwargs)

            dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'distributed_master',
                           'f_kwargs': {'node_id': 'master'}, 'nodes': ['master']}
            raise_if_exc_routine(dapi_kwargs=dapi_kwargs)

            expected = AffectedItemsWazuhResult()
            expected.affected_items = [{'id': '001', 'node_name': 'master'}]
            with patch('wazuh.agent.get_agents_in_group', return_value=expected):
                dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'distributed_master',
                               'f_kwargs': {'group_id': 'default'}, 'nodes': ['master']}
                raise_if_exc_routine(dapi_kwargs=dapi_kwargs)

            expected.affected_items = []
            with patch('wazuh.agent.get_agents_in_group', return_value=expected):
                dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'distributed_master',
                               'f_kwargs': {'group_id': 'noexist'}, 'nodes': ['master']}
                raise_if_exc_routine(dapi_kwargs=dapi_kwargs)

            dapi_kwargs = {'f': manager.status, 'logger': logger, 'request_type': 'distributed_master',
                           'f_kwargs': {'node_list': '*'}, 'broadcasting': True, 'nodes': ['master']}
            raise_if_exc_routine(dapi_kwargs=dapi_kwargs)


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
@patch('wazuh.core.cluster.dapi.dapi.node_info', {'node': 'random_node'})
def test_DistributedAPI_check_wazuh_status_exception(status_value):
    """Test exceptions from `check_wazuh_status` method from class DistributedAPI."""
    statuses = {process: status_value for process in sorted(get_manager_status())}
    with patch('wazuh.core.manager.get_manager_status',
               return_value=statuses):
        dapi = DistributedAPI(f=agent.get_agents_summary_status, logger=logger)
        try:
            dapi.check_wazuh_status()
        except WazuhInternalError as e:
            assert e.code == 1017
            assert statuses
            assert e._extra_message['node_name'] == 'random_node'
            extra_message = ', '.join([f'{key}->{statuses[key]}' for key in dapi.basic_services if key in statuses])
            assert e._extra_message['not_ready_daemons'] == extra_message


@patch("asyncio.Queue")
def test_APIRequestQueue_init(queue_mock):
    """Test `APIRequestQueue` constructor."""
    server = DistributedAPI(f=agent.get_agents_summary_status, logger=logger)
    api_request_queue = APIRequestQueue(server=server)
    api_request_queue.add_request(b'testing')
    assert api_request_queue.server == server
    queue_mock.assert_called_once()


@patch("wazuh.core.cluster.common.import_module", return_value="os.path")
@patch("asyncio.get_event_loop")
async def test_APIRequestQueue_run(loop_mock, import_module_mock):
    """Test `APIRequestQueue.run` function."""

    class DistributedAPI_mock:
        def __init__(self):
            pass

        async def distribute_function(self):
            pass

    class NodeMock:
        async def send_request(self, command, data):
            pass

        async def send_string(self, command):
            return command

    class ServerMock:
        def __init__(self):
            self.clients = {"names": ["w1", "w2"]}

    class RequestQueueMock:
        async def get(self):
            return 'wazuh*request_queue*test ' \
                   '{"f": {"__callable__": {"__name__": "join", "__qualname__": "join", "__module__": "join"}}}'

    with patch.object(logger, "error", side_effect=Exception("break while true")) as logger_mock:
        server = ServerMock()
        apirequest = APIRequestQueue(server=server)
        apirequest.logger = logger
        apirequest.request_queue = RequestQueueMock()
        with pytest.raises(Exception, match=".*break while true.*"):
            await apirequest.run()
        logger_mock.assert_called_once_with("Error in DAPI request. The destination node is "
                                            "not connected or does not exist: 'wazuh'.")

        node = NodeMock()
        with patch.object(node, "send_request", side_effect=WazuhClusterError(3020, extra_message="test")):
            with patch.object(node, "send_string", return_value=b"noerror"):
                with patch("wazuh.core.cluster.dapi.dapi.DistributedAPI", return_value=DistributedAPI_mock()):
                    server.clients = {"wazuh": node}
                    with pytest.raises(Exception):
                        await apirequest.run()

            with patch.object(node, "send_string", Exception("break while true")):
                with patch("wazuh.core.cluster.dapi.dapi.DistributedAPI", return_value=DistributedAPI_mock()):
                    with patch("wazuh.core.cluster.dapi.dapi.contextlib.suppress", side_effect=Exception()):
                        apirequest.logger = logging.getLogger("apirequest")
                        with pytest.raises(Exception):
                            await apirequest.run()


@patch("wazuh.core.cluster.dapi.dapi.contextlib.suppress", side_effect=Exception())
@patch("asyncio.get_event_loop")
async def test_SendSyncRequestQueue_run(loop_mock, contexlib_mock):
    """Test `SendSyncRequestQueue.run` function."""

    class NodeMock:
        async def send_request(self, command, data):
            pass

        async def send_string(self, command):
            return command

    class ServerMock:
        def __init__(self):
            self.clients = {"names": ["w1", "w2"]}

    class RequestQueueMock:
        async def get(self):
            return "wazuh*request_queue*test {\"daemon_name\": \"test\"}"

    with patch.object(logger, "error", side_effect=Exception("break while true")) as logger_mock:
        server = ServerMock()
        sendsync = SendSyncRequestQueue(server=server)
        sendsync.logger = logger
        sendsync.request_queue = RequestQueueMock()
        with pytest.raises(Exception, match=".*break while true.*"):
            await sendsync.run()
        logger_mock.assert_called_once_with("Error in Sendsync. The destination node is "
                                            "not connected or does not exist: 'wazuh'.")

        node = NodeMock()
        with patch.object(node, "send_request", Exception("break while true")):
            with patch("wazuh.core.cluster.dapi.dapi.wazuh_sendsync", side_effect=Exception("break while true")):
                server.clients = {"wazuh": node}
                sendsync.logger = logging.getLogger("sendsync")
                with pytest.raises(Exception):
                    await sendsync.run()

            with patch("wazuh.core.cluster.dapi.dapi.wazuh_sendsync", side_effect="noerror"):
                with pytest.raises(Exception):
                    await sendsync.run()
