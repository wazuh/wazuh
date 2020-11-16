import sys
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.common.getgrnam'):
    with patch('wazuh.common.getpwnam'):
        with patch('wazuh.common.ossec_uid'):
            with patch('wazuh.common.ossec_gid'):
                sys.modules['wazuh.rbac.orm'] = MagicMock()

                from wazuh.core.cluster import control
                from wazuh.core.cluster.local_client import LocalClient
                from wazuh import WazuhInternalError, WazuhError


async def async_local_client(command, data, wait_for_complete):
    return None


@pytest.mark.asyncio
async def test_get_nodes():
    """Verify that get_nodes function returns the cluster nodes list."""
    local_client = LocalClient()
    with patch('wazuh.core.cluster.local_client.LocalClient.execute', side_effect=async_local_client):
        expected_result = {'items': [{'name': 'master'}, {'name': 'worker1'}], 'totalItems': 2}
        with patch('json.loads', return_value=expected_result):
            result = await control.get_nodes(lc=local_client)
            assert result == expected_result

            result_q = await control.get_nodes(lc=local_client, q='name=master')
            assert result_q == {'items': [{'name': 'master'}], 'totalItems': 1}

        with patch('json.loads', return_value=KeyError(1)):
            with pytest.raises(KeyError):
                await control.get_nodes(lc=local_client)


@pytest.mark.asyncio
async def test_get_node():
    """Verify that get_node function returns the current node name."""
    local_client = LocalClient()
    with patch('wazuh.core.cluster.local_client.LocalClient.execute', side_effect=async_local_client):
        expected_result = [{'items': [{'name': 'master'}]}, {'items': []}]
        for expected in expected_result:
            with patch('json.loads', return_value=expected):
                result = await control.get_node(lc=local_client)
                if len(expected['items']) > 0:
                    assert result == expected['items'][0]
                else:
                    assert result == {}

        with patch('json.loads', return_value=KeyError(1)):
            with pytest.raises(KeyError):
                await control.get_node(lc=local_client)


@pytest.mark.asyncio
async def test_get_health():
    """Verify that get_health function returns the current node health."""
    local_client = LocalClient()
    with patch('wazuh.core.cluster.local_client.LocalClient.execute', side_effect=async_local_client):
        expected_result = [{'items': [{'name': 'master'}]}, {'items': []}]
        for expected in expected_result:
            with patch('json.loads', return_value=expected):
                result = await control.get_health(lc=local_client)
                assert result == expected

        with patch('json.loads', return_value=KeyError(1)):
            with pytest.raises(KeyError):
                await control.get_health(lc=local_client)


@pytest.mark.asyncio
async def test_get_agents():
    """Verify that get_agents function returns the health of the agents connected through the current node."""
    local_client = LocalClient()
    with patch('wazuh.core.cluster.local_client.LocalClient.execute', side_effect=async_local_client):
        expected_result = [{'items': [{'name': 'master'}]}, {'items': []}]
        for expected in expected_result:
            with patch('json.loads', return_value=expected):
                result = await control.get_agents(lc=local_client)
                assert result == expected

        with patch('json.loads', return_value=KeyError(1)):
            with pytest.raises(KeyError):
                await control.get_agents(lc=local_client)


@pytest.mark.asyncio
async def test_get_system_nodes():
    """Verify that get_system_nodes function returns the name of all cluster nodes."""
    with patch('wazuh.core.cluster.local_client.LocalClient.execute', side_effect=async_local_client):
        expected_result = [{'items': [{'name': 'master'}]}]
        for expected in expected_result:
            with patch('wazuh.core.cluster.control.get_nodes', return_value=expected):
                result = await control.get_system_nodes()
                assert result == [expected['items'][0]['name']]

        expected_exception = WazuhInternalError(3012)
        with patch('wazuh.core.cluster.control.get_nodes', side_effect=WazuhInternalError(3012)):
            result = await control.get_system_nodes()
            assert result == WazuhError(3013)
