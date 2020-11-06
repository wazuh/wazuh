import sys
from unittest.mock import MagicMock, patch

import pytest

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']

        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh import cluster
        from wazuh.core import common
        from wazuh.core.exception import WazuhError, WazuhResourceNotFound
        from wazuh.core.cluster.local_client import LocalClient
        from wazuh.core.results import WazuhResult

default_config = {'disabled': True, 'node_type': 'master', 'name': 'wazuh', 'node_name': 'node01',
                  'key': '', 'port': 1516, 'bind_addr': '0.0.0.0', 'nodes': ['NODE_IP'], 'hidden': 'no'}


@patch('wazuh.cluster.read_config', return_value=default_config)
def test_read_config_wrapper(mock_read_config):
    """Verify that the read_config_wrapper returns the default configuration."""
    result = cluster.read_config_wrapper()
    assert result.affected_items == [default_config]


@patch('wazuh.cluster.read_config', side_effect=WazuhError(1001))
def test_read_config_wrapper_exception(mock_read_config):
    """Verify the exceptions raised in read_config_wrapper."""
    result = cluster.read_config_wrapper()
    assert list(result.failed_items.keys())[0] == WazuhError(1001)


@patch('wazuh.cluster.read_config', return_value=default_config)
def test_node_wrapper(mock_read_config):
    """Verify that the node_wrapper returns the default node information."""
    result = cluster.get_node_wrapper()
    assert result.affected_items == [{'cluster': default_config["name"],
                                      'node': default_config["node_name"],
                                      'type': default_config["node_type"]}]


@patch('wazuh.cluster.get_node', side_effect=WazuhError(1001))
def test_node_wrapper_exception(mock_get_node):
    """Verify the exceptions raised in get_node_wrapper."""
    result = cluster.get_node_wrapper()
    assert list(result.failed_items.keys())[0] == WazuhError(1001)


def test_get_status_json():
    """Verify that get_status_json returns the default status information."""
    result = cluster.get_status_json()
    expected = WazuhResult({'data': {"enabled": "no" if default_config['disabled'] else "yes", "running": "no"}})
    assert result == expected


@pytest.mark.asyncio
@patch('wazuh.core.cluster.local_client.LocalClient.start', side_effect=None)
async def test_get_health_nodes(mock_unix_connection):
    """Verify that get_health_nodes returns the health of all nodes."""

    async def async_mock(lc=None, filter_node=None):
        return {'nodes': {'manager': {'info': {'name': 'master'}}}}

    local_client = LocalClient()
    with patch('wazuh.cluster.get_health', side_effect=async_mock):
        result = await cluster.get_health_nodes(lc=local_client)
    expected = await async_mock()

    assert result.affected_items == [expected['nodes']['manager']]


@pytest.mark.asyncio
async def test_get_nodes_info():
    """Verify that get_nodes_info returns the information of all nodes."""

    async def valid_node(lc=None, filter_node=None):
        return {'items': ['master', 'worker1'], 'totalItems': 2}

    local_client = LocalClient()
    common.cluster_nodes.set(['master', 'worker1', 'worker2'])
    with patch('wazuh.cluster.get_nodes', side_effect=valid_node):
        result = await cluster.get_nodes_info(lc=local_client, filter_node=['master', 'worker1', 'noexists'])
    expected = await valid_node()

    assert result.affected_items == expected['items']
    assert result.total_affected_items == expected['totalItems']
    assert result.failed_items[WazuhResourceNotFound(1730)] == {'noexists'}
    assert result.total_failed_items == 1
