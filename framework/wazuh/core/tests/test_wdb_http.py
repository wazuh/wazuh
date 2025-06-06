from unittest.mock import AsyncMock, call, MagicMock

import pytest
from wazuh.core.wdb_http import AgentIDGroups, AgentsSummary, APPLICATION_JSON, WazuhDBHTTPClient
from wazuh.core.exception import WazuhError


class TestWazuhDBHTTPClient:
    """Test the functionality of the `WazuhDBHTTPClient` class."""

    @pytest.fixture
    def client_mock(self) -> AsyncMock:
        """Provide a mock client instance for testing."""
        return AsyncMock()

    @pytest.fixture
    def module_instance(self, client_mock: AsyncMock) -> WazuhDBHTTPClient:
        """Provide an instance of VulnerabilityModule with a mocked client for testing."""
        client = WazuhDBHTTPClient()
        client._client = client_mock
        return client

    async def test__get(self, client_mock: AsyncMock, module_instance: WazuhDBHTTPClient):
        """Check that the `_get` method works as expected."""
        response = MagicMock()
        response.is_error = False
        client_mock.get.return_value = response

        await module_instance._get('/agents')
        client_mock.assert_has_calls([
            call.get(url='http://localhost/v1/agents', headers={'Accept': APPLICATION_JSON}),
            call.get().json()
        ])

    async def test__get_ko(self, client_mock: AsyncMock, module_instance: WazuhDBHTTPClient):
        """Check that the `_get` handles exceptions successfully."""
        response = MagicMock()
        response.is_error = True
        response.text = 'Service Unavailable: failure'
        client_mock.get.return_value = response

        expected_error_msg = 'Error 2012 - Invalid wazuh-db HTTP request: Service Unavailable: failure'
        with pytest.raises(WazuhError, match=expected_error_msg):
            await module_instance._get('/agents')
    
    async def test__post(self, client_mock: AsyncMock, module_instance: WazuhDBHTTPClient):
        """Check that the `_post` method works as expected."""
        response = MagicMock()
        response.is_error = False
        client_mock.post.return_value = response

        await module_instance._post('/agents', b'')
        client_mock.assert_has_calls([
            call.post(
                url='http://localhost/v1/agents',
                json=b'',
                headers={'Accept': APPLICATION_JSON, 'Content-Type': APPLICATION_JSON}
            ),
            call.post().json()
        ])

    async def test__post_ko(self, client_mock: AsyncMock, module_instance: WazuhDBHTTPClient):
        """Check that the `_post` handles exceptions successfully."""
        response = MagicMock()
        response.is_error = True
        response.text = 'Service Unavailable: failure'
        client_mock.post.return_value = response

        expected_error_msg = 'Error 2012 - Invalid wazuh-db HTTP request: Service Unavailable: failure'
        with pytest.raises(WazuhError, match=expected_error_msg):
            await module_instance._post('/agents', b'')

    async def test_get_agents_ids(self, client_mock: AsyncMock, module_instance: WazuhDBHTTPClient):
        """Check that the `get_agents_ids` method works as expected."""
        expected_result = [1, 2, 3]
        response = MagicMock()
        response.is_error = False
        response.json.return_value = expected_result
        client_mock.get.return_value = response

        result = await module_instance.get_agents_ids()
        assert result == expected_result
        client_mock.assert_has_calls([
            call.get(url='http://localhost/v1/agents/ids', headers={'Accept': APPLICATION_JSON}),
            call.get().json()
        ])

    async def test_get_agent_groups(self, client_mock: AsyncMock, module_instance: WazuhDBHTTPClient):
        """Check that the `get_agent_groups` method works as expected."""
        agent_id = 1
        expected_result = ['default', 'test']
        response = MagicMock()
        response.is_error = False
        response.json.return_value = expected_result
        client_mock.get.return_value = response

        result = await module_instance.get_agent_groups(agent_id)
        assert result == expected_result
        client_mock.assert_has_calls([
            call.get(url=f'http://localhost/v1/agents/{agent_id}/groups', headers={'Accept': APPLICATION_JSON}),
            call.get().json()
        ])

    async def test_get_agents_groups(self, client_mock: AsyncMock, module_instance: WazuhDBHTTPClient):
        """Check that the `get_agents_groups` method works as expected."""
        expected_result = [
            AgentIDGroups(id='001', groups=['default']),
            AgentIDGroups(id='002', groups=['default', 'test']),
        ]
        response = MagicMock()
        response.is_error = False
        response.json.return_value = {'data': {
            '1': ['default'],
            '2': ['default','test']
        }}
        client_mock.get.return_value = response

        result = await module_instance.get_agents_groups()
        for i, item in enumerate(result):
            assert item.id == expected_result[i].id
            assert item.groups == expected_result[i].groups

        client_mock.assert_has_calls([
            call.get(url='http://localhost/v1/agents/ids/groups', headers={'Accept': APPLICATION_JSON}),
            call.get().json()
        ])

    async def test_get_group_agents(self, client_mock: AsyncMock, module_instance: WazuhDBHTTPClient):
        """Check that the `get_group_agents` method works as expected."""
        group_name = 'test'
        expected_result = [2, 5, 11]
        response = MagicMock()
        response.is_error = False
        response.json.return_value = expected_result
        client_mock.get.return_value = response

        result = await module_instance.get_group_agents(group_name)
        assert result == expected_result
        client_mock.assert_has_calls([
            call.get(url=f'http://localhost/v1/agents/ids/groups/{group_name}', headers={'Accept': APPLICATION_JSON}),
            call.get().json()
        ])
    
    async def test_get_agents_summary(self, client_mock: AsyncMock, module_instance: WazuhDBHTTPClient):
        """Check that the `get_agents_summary` method works as expected."""
        agent_ids = [1, 2, 3]
        expected_result = AgentsSummary(
            agents_by_groups={
                'default': 30,
                'test': 30
            },
            agents_by_os={
                'amzn': 30,
            },
            agents_by_status={
                'active': 10,
                'disconnected': 20
            },
        )
        response = MagicMock()
        response.is_error = False
        response.json.return_value = {
            'agents_by_groups': {
                'default': 30,
                'test': 30
            },
            'agents_by_os': {
                'amzn': 30
            },
            'agents_by_status': {
                'active': 10,
                'disconnected': 20
            },
        }
        client_mock.post.return_value = response

        result = await module_instance.get_agents_summary(agent_ids)
        assert result.groups == expected_result.groups
        assert result.os == expected_result.os
        assert result.status == expected_result.status

        client_mock.assert_has_calls([
            call.post(
                url='http://localhost/v1/agents/summary',
                json=agent_ids,
                headers={'Accept': APPLICATION_JSON, 'Content-Type': APPLICATION_JSON}
            ),
            call.post().json()
        ])

    async def test_get_agents_sync(self, client_mock: AsyncMock, module_instance: WazuhDBHTTPClient):
        """Check that the `get_agents_sync` method works as expected."""
        expected_result = {
            'syncreq': [
                {
                    'id': 10,
                    'name': 'b922117b0323',
                    'ip': '172.18.0.9',
                    'node_name': 'node01',
                    'last_keepalive': 1745892111,
                    'connection_status': 'active',
                    'disconnection_time': 0,
                    'group_config_status': 'synced',
                    'status_code': 0,
                    'labels': []
                }
            ],
            'syncreq_keepalive': [],
            'syncreq_status': [],
        }
        response = MagicMock()
        response.is_error = False
        response.json.return_value = expected_result
        client_mock.get.return_value = response

        result = await module_instance.get_agents_sync()
        assert result == expected_result

        client_mock.assert_has_calls([
            call.get(
                url='http://localhost/v1/agents/sync',
                headers={'Accept': APPLICATION_JSON}
            ),
            call.get().json()
        ])
    
    async def test_set_agents_sync(self, client_mock: AsyncMock, module_instance: WazuhDBHTTPClient):
        """Check that the `set_agents_sync` method works as expected."""
        agents_sync = {
            'syncreq': [
                {
                    'id': '010',
                    'name': 'b922117b0323',
                    'ip': '172.18.0.9',
                    'node_name': 'node01',
                    'last_keepalive': 1745892111,
                    'connection_status': 'active',
                    'disconnection_time': 0,
                    'group_config_status': 'synced',
                    'status_code': 0,
                    'labels': []
                }
            ],
            'syncreq_keepalive': [],
            'syncreq_status': [],
        }
        response = MagicMock()
        response.is_error = False
        client_mock.post.return_value = response

        await module_instance.set_agents_sync(agents_sync)

        client_mock.assert_has_calls([
            call.post(
                url='http://localhost/v1/agents/sync',
                json=agents_sync,
                headers={'Accept': APPLICATION_JSON, 'Content-Type': APPLICATION_JSON},
            ),
        ])
