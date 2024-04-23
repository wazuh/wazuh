from typing import Optional
from unittest import mock

import pytest
from wazuh.agent import get_agents, reconnect_agents
from wazuh.cluster import get_nodes_info
from wazuh.core.results import AffectedItemsWazuhResult

from framework.wazuh.core.cluster.hap_helper.wazuh import WazuhAgent, WazuhDAPI


class TestWazuhAgent:
    @pytest.mark.parametrize('version,expected', [('v4.2.0', False), ('v4.3.0', True), ('v4.4.0', True)])
    def test_can_reconnect(self, version: str, expected: bool):
        """Check the correct output of `can_reconnect` function."""

        assert WazuhAgent.can_reconnect(version) == expected

    def test_get_agents_able_to_reconnect(self):
        """Check the correct output of `get_agents_able_to_reconnect` function."""

        agents = [
            {'id': 1, 'version': 'v4.2.0'},
            {'id': 2, 'version': 'v4.3.0'},
            {'id': 3, 'version': 'v4.4.0'},
        ]

        assert WazuhAgent.get_agents_able_to_reconnect(agents_list=agents) == [2, 3]


@mock.patch('framework.wazuh.core.cluster.hap_helper.wazuh.DistributedAPI', autospec=True)
class TestWazuhDAPI:
    wazuh_dapi = WazuhDAPI(tag='test')

    @pytest.fixture
    def fixture_affected_items_result(self):
        return AffectedItemsWazuhResult()

    @pytest.mark.parametrize(
        'nodes_data,excluded_nodes',
        (
            (
                [
                    {'name': 'worker1', 'ip': '192.168.0.1'},
                    {'name': 'worker2', 'ip': '192.168.0.2'},
                    {'name': 'worker3', 'ip': '192.168.0.3'},
                ],
                [],
            ),
            (
                [
                    {'name': 'worker1', 'ip': '192.168.0.1'},
                    {'name': 'worker2', 'ip': '192.168.0.2'},
                    {'name': 'worker3', 'ip': '192.168.0.3'},
                ],
                ['worker1'],
            ),
        ),
    )
    @mock.patch('framework.wazuh.core.cluster.hap_helper.wazuh.get_system_nodes', return_value={})
    async def test_get_cluster_nodes(
        self,
        get_system_nodes_mock: mock.AsyncMock,
        dapi_mock: mock.MagicMock,
        fixture_affected_items_result: AffectedItemsWazuhResult,
        nodes_data: list,
        excluded_nodes: list,
    ):
        """Check the correct output of `get_cluster_nodes` function."""

        self.wazuh_dapi.excluded_nodes = excluded_nodes
        fixture_affected_items_result.affected_items = nodes_data
        dapi_mock.return_value.distribute_function.return_value = fixture_affected_items_result

        ret_val = await self.wazuh_dapi.get_cluster_nodes()

        dapi_mock.assert_called_once_with(
            f=get_nodes_info,
            f_kwargs=None,
            logger=self.wazuh_dapi.logger,
            request_type='local_master',
            is_async=True,
            local_client_arg='lc',
            nodes={},
        )
        assert ret_val == {item['name']: item['ip'] for item in nodes_data if item['name'] not in excluded_nodes}

    async def test_reconnect_agents(
        self,
        dapi_mock: mock.MagicMock,
        fixture_affected_items_result: AffectedItemsWazuhResult,
    ):
        """Check the correct output of `reconnect_agents` function."""

        agent_list = [1, 2, 3]
        fixture_affected_items_result.affected_items = agent_list
        dapi_mock.return_value.distribute_function.return_value = fixture_affected_items_result

        ret_val = await self.wazuh_dapi.reconnect_agents(agent_list=agent_list)

        dapi_mock.assert_called_once_with(
            f=reconnect_agents,
            f_kwargs={'agent_list': agent_list},
            logger=self.wazuh_dapi.logger,
            request_type='distributed_master',
            wait_for_complete=True,
        )
        assert ret_val == agent_list

    async def test_get_agents_node_distribution(
        self,
        dapi_mock: mock.MagicMock,
        fixture_affected_items_result: AffectedItemsWazuhResult,
    ):
        """Check the correct output of `get_agents_node_distribution` function."""

        agents_data = [
            {'id': 1, 'name': 'agent1', 'version': '4.9.0', 'node_name': 'worker1'},
            {'id': 2, 'name': 'agent2', 'version': '4.9.0', 'node_name': 'worker2'},
        ]
        fixture_affected_items_result.affected_items = agents_data
        dapi_mock.return_value.distribute_function.return_value = fixture_affected_items_result

        ret_val = await self.wazuh_dapi.get_agents_node_distribution()

        dapi_mock.assert_called_once_with(
            f=get_agents,
            f_kwargs={
                'select': ['node_name', 'version'],
                'sort': {'fields': ['version', 'id'], 'order': 'desc'},
                'filters': {'status': 'active'},
                'q': 'id!=000',
                'limit': self.wazuh_dapi.AGENTS_MAX_LIMIT,
            },
            logger=self.wazuh_dapi.logger,
            request_type='local_master',
        )
        assert ret_val == {'worker1': [{'id': 1, 'version': '4.9.0'}], 'worker2': [{'id': 2, 'version': '4.9.0'}]}

    @pytest.mark.parametrize('limit', [100, None])
    async def test_get_agents_belonging_to_node(
        self, dapi_mock: mock.MagicMock, fixture_affected_items_result: AffectedItemsWazuhResult, limit: Optional[int]
    ):
        """Check the correct output of `get_agents_belonging_to_node` function."""

        agents_data = [
            {'id': 1, 'name': 'agent1', 'version': '4.9.0'},
            {'id': 2, 'name': 'agent2', 'version': '4.9.0'},
        ]
        fixture_affected_items_result.affected_items = agents_data
        dapi_mock.return_value.distribute_function.return_value = fixture_affected_items_result

        node_name = 'worker1'

        ret_val = await self.wazuh_dapi.get_agents_belonging_to_node(node_name=node_name, limit=limit)

        dapi_mock.assert_called_once_with(
            f=get_agents,
            f_kwargs={
                'select': ['version'],
                'sort': {'fields': ['version', 'id'], 'order': 'desc'},
                'filters': {'status': 'active', 'node_name': node_name},
                'q': 'id!=000',
                'limit': limit or self.wazuh_dapi.AGENTS_MAX_LIMIT,
            },
            logger=self.wazuh_dapi.logger,
            request_type='local_master',
        )
        assert ret_val == agents_data
