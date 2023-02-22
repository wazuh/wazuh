import json
import sys
from unittest.mock import patch, MagicMock, call, ANY

import pytest

from wazuh.core.exception import WazuhClusterError

with patch('wazuh.common.getgrnam'):
    with patch('wazuh.common.getpwnam'):
        with patch('wazuh.common.wazuh_uid'):
            with patch('wazuh.common.wazuh_gid'):
                sys.modules['wazuh.rbac.orm'] = MagicMock()

                from wazuh.core.cluster import control
                from wazuh.core.cluster.local_client import LocalClient
                from wazuh import WazuhInternalError, WazuhError
                from wazuh.core.cluster.common import WazuhJSONEncoder


@pytest.mark.asyncio
async def test_get_cluster_data():
    """Verify that LocalClient.execute is called with expected params and exceptions are correctly raised."""
    async def async_local_client(command, data):
        return None

    local_client = LocalClient()
    with patch('wazuh.core.cluster.local_client.LocalClient.execute', side_effect=async_local_client) as mock_execute:
        expected_result = {'test': 'value'}
        with patch('json.loads', return_value=expected_result):
            assert expected_result == await control.get_cluster_data(local_client, command='get_test')
            mock_execute.assert_called_once_with(command=b'get_test', data=b'')

        with patch('wazuh.core.cluster.local_client.LocalClient.execute',
                   side_effect=[WazuhClusterError(3020), json.dumps(WazuhError(1000), cls=WazuhJSONEncoder)]):
            with pytest.raises(WazuhClusterError):
                await control.get_cluster_data(lc=local_client, command='get_test', data='test_data')

            with pytest.raises(WazuhError):
                await control.get_cluster_data(lc=local_client, command='get_test', data='test_data')


@pytest.mark.asyncio
@patch('wazuh.core.cluster.control.get_cluster_data', return_value={'items': [{'name': 'master'}, {'name': 'worker1'}]})
async def test_get_nodes(get_cluster_data_mock):
    """Verify that get_nodes function returns the cluster nodes list."""
    local_client = LocalClient()
    result = await control.get_nodes(lc=local_client)
    assert result == {'items': [{'name': 'master'}, {'name': 'worker1'}]}

    result_q = await control.get_nodes(lc=local_client, q='name=master')
    assert result_q == {'items': [{'name': 'master'}], 'totalItems': 1}
    get_cluster_data_mock.assert_has_calls(
        [call(local_client, 'get_nodes', '{"filter_node": null, "offset": 0, "limit": 500, "sort": null, '
                                         '"search": null, "select": null, "filter_type": "all"}')]*2)


@pytest.mark.asyncio
@pytest.mark.parametrize('get_cluster_data_response, expected_response', [
    ({'items': [{'name': 'master'}, {'name': 'worker1'}]}, {'name': 'master'}),
    ({'items': []}, {}),
])
@patch('wazuh.core.cluster.control.get_cluster_data')
async def test_get_node(get_cluster_data_mock, get_cluster_data_response, expected_response):
    """Verify that get_node function returns the current node name."""
    local_client = LocalClient()
    get_cluster_data_mock.return_value = get_cluster_data_response
    result = await control.get_node(lc=local_client, filter_node='master', select='test')
    assert result == expected_response
    get_cluster_data_mock.assert_called_once_with(local_client, 'get_nodes',
                                                  '{"filter_node": "master", "offset": 0, "limit": 500, "sort": null, '
                                                  '"search": null, "select": "test", "filter_type": "all"}')


@pytest.mark.asyncio
@patch('wazuh.core.cluster.control.get_cluster_data')
async def test_get_health(get_cluster_data_mock):
    """Verify that get_health function calls 'get_cluster_data' with expected params."""
    local_client = LocalClient()
    await control.get_health(lc=local_client, filter_node=['test1', 'test2'])
    get_cluster_data_mock.assert_called_once_with(local_client,  'get_health', '["test1", "test2"]')


@pytest.mark.asyncio
@patch('wazuh.core.cluster.control.get_cluster_data', return_value={'items': [{'name': 'master', 'id': '001'}]})
async def test_get_agents(get_cluster_data_mock):
    """Verify that get_agents function returns the health of the agents connected through the current node."""
    local_client = LocalClient()
    result = await control.get_agents(lc=local_client, filter_status=['active'])
    assert result == {'items': [{'name': 'master', 'id': '001', 'status': 'unknown', 'node_name': 'unknown',
                                 'version': 'unknown', 'ip': 'unknown'}]}
    get_cluster_data_mock.assert_called_once_with(local_client, 'dapi', ANY)


@pytest.mark.asyncio
async def test_get_system_nodes():
    """Verify that get_system_nodes function returns the name of all cluster nodes."""
    async def async_local_client(command, data):
        return None

    with patch('wazuh.core.cluster.local_client.LocalClient.execute', side_effect=async_local_client):
        expected_result = [{'items': [{'name': 'master'}]}]
        for expected in expected_result:
            with patch('wazuh.core.cluster.control.get_nodes', return_value=expected):
                result = await control.get_system_nodes()
                assert result == [expected['items'][0]['name']]

        with patch('wazuh.core.cluster.control.get_nodes', side_effect=WazuhInternalError(3012)):
            result = await control.get_system_nodes()
            assert result == WazuhError(3013)

    with patch('wazuh.core.cluster.local_client.LocalClient.execute', side_effect=[WazuhClusterError(3020), 'error']):
        with pytest.raises(WazuhClusterError):
            await control.get_system_nodes()

        with pytest.raises(json.JSONDecodeError):
            await control.get_system_nodes()


@pytest.mark.asyncio
@patch('wazuh.core.cluster.control.get_cluster_data')
async def test_get_node_ruleset_integrity(get_cluster_data_mock):
    """Verify that get_node_ruleset_integrity function calls 'get_cluster_data' with expected params."""
    local_client = LocalClient()
    await control.get_node_ruleset_integrity(lc=local_client)
    get_cluster_data_mock.assert_called_once_with(local_client,  'get_hash')


@pytest.mark.asyncio
@patch('wazuh.core.cluster.control.get_cluster_data')
async def test_get_cluster_json_conf(get_cluster_data_mock):
    """Verify that get_cluster_json_conf function calls 'get_cluster_data' with expected params."""
    local_client = LocalClient()
    await control.get_cluster_json_conf(lc=local_client)
    get_cluster_data_mock.assert_called_once_with(local_client,  'get_cl_conf')
