from asyncio import TimeoutError, wait_for
from random import choice
from unittest import mock
from unittest.mock import patch

import pytest
from wazuh.core.cluster.utils import (
    AGENT_CHUNK_SIZE,
    AGENT_RECONNECTION_STABILITY_TIME,
    AGENT_RECONNECTION_TIME,
    CLIENT_CERT,
    CLIENT_CERT_KEY,
    CLIENT_CERT_PASSWORD,
    EXCLUDED_NODES,
    FREQUENCY,
    HAPROXY_ADDRESS,
    HAPROXY_BACKEND,
    HAPROXY_CERT,
    HAPROXY_PASSWORD,
    HAPROXY_PORT,
    HAPROXY_PROTOCOL,
    HAPROXY_RESOLVER,
    HAPROXY_USER,
    IMBALANCE_TOLERANCE,
    REMOVE_DISCONNECTED_NODE_AFTER,
)
from wazuh.core.config.client import CentralizedConfig, Config
from wazuh.core.config.models.indexer import IndexerConfig, IndexerNode
from wazuh.core.config.models.server import NodeConfig, NodeType, ServerConfig, SSLConfig, ValidateFilePathMixin
from wazuh.core.exception import WazuhException

with patch.object(ValidateFilePathMixin, '_validate_file_path', return_value=None):
    default_config = Config(
        server=ServerConfig(
            nodes=['0'],
            node=NodeConfig(
                name='node_name', type=NodeType.MASTER, ssl=SSLConfig(key='example', cert='example', ca='example')
            ),
        ),
        indexer=IndexerConfig(hosts=[IndexerNode(host='example', port=1516)], username='wazuh', password='wazuh'),
    )
    CentralizedConfig._config = default_config

    from wazuh.core.cluster.hap_helper.hap_helper import HAPHelper, ProxyServerState, WazuhHAPHelperError


class TestHAPHelper:
    CONFIGURATION = {
        'sleep_time': 60,
        'agent_reconnection_stability_time': 10,
        'agent_reconnection_time': 1,
        'agent_reconnection_chunk_size': 5,
        'agent_tolerance': 0.1,
        'remove_disconnected_node_after': 3,
    }

    @pytest.fixture
    def dapi_mock(self):
        with mock.patch('wazuh.core.cluster.hap_helper.hap_helper.WazuhDAPI', autospec=True) as dapi_mock:
            yield dapi_mock

    @pytest.fixture
    def proxy_api_mock(self):
        with mock.patch('wazuh.core.cluster.hap_helper.hap_helper.ProxyAPI', autospec=True) as proxy_api_mock:
            yield proxy_api_mock

    @pytest.fixture
    def proxy_mock(self):
        with mock.patch('wazuh.core.cluster.hap_helper.hap_helper.Proxy', autospec=True) as proxy_mock:
            yield proxy_mock

    @pytest.fixture
    def helper(self, proxy_mock: mock.MagicMock, dapi_mock: mock.MagicMock):
        helper = HAPHelper(proxy=proxy_mock, wazuh_dapi=dapi_mock, tag='test', **self.CONFIGURATION)
        with mock.patch.object(helper, 'logger'):
            yield helper

    @pytest.fixture
    def sleep_mock(self):
        with mock.patch('wazuh.core.cluster.hap_helper.hap_helper.asyncio.sleep') as sleep_mock:
            yield sleep_mock

    @pytest.fixture
    def wazuh_agent_mock(self):
        with mock.patch(
            'wazuh.core.cluster.hap_helper.hap_helper.WazuhAgent.get_agents_able_to_reconnect', autospec=True
        ) as wazuh_agent_mock:
            yield wazuh_agent_mock

    async def test_initialize_proxy(self, helper: HAPHelper, proxy_mock: mock.MagicMock):
        """Check the correct function of `initialize_proxy` method."""
        await helper.initialize_proxy()
        proxy_mock.initialize.assert_called_once()

    async def test_initialize_proxy_ko(self, helper: HAPHelper, proxy_mock: mock.MagicMock):
        """Check the correct error handling of `initialize_proxy` method."""
        proxy_mock.initialize.side_effect = WazuhHAPHelperError(3046)

        with pytest.raises(WazuhHAPHelperError):
            await helper.initialize_proxy()
            assert helper.logger.critical.call_count == 2

    @pytest.mark.parametrize(
        'exists_backend,exists_frontend', ([True, True], [True, False], [False, True], [False, False])
    )
    async def test_initialize_wazuh_cluster_configuration(
        self, helper: HAPHelper, proxy_mock: mock.MagicMock, exists_backend: bool, exists_frontend: bool
    ):
        """Check that `initialize_wazuh_cluster_configuration` method makes the correct callbacks."""
        backend_name = 'test'
        frontend_name = f'{backend_name}_front'
        port = 1514

        proxy_mock.wazuh_backend = backend_name
        proxy_mock.wazuh_connection_port = port
        proxy_mock.exists_backend.return_value = exists_backend
        proxy_mock.exists_frontend.return_value = exists_frontend

        await helper.initialize_wazuh_cluster_configuration()

        proxy_mock.exists_backend.assert_called_once_with(backend_name)
        if not exists_backend:
            proxy_mock.add_new_backend.assert_called_once_with(backend_name)
        else:
            proxy_mock.add_new_backend.assert_not_called()

        proxy_mock.exists_frontend.assert_called_once_with(frontend_name)
        if not exists_frontend:
            proxy_mock.add_new_frontend.assert_called_once_with(name=frontend_name, port=port, backend=backend_name)
        else:
            proxy_mock.add_new_frontend.assert_not_called()

    @pytest.mark.parametrize(
        'stats,expected',
        (
            [
                {
                    'status': ProxyServerState.UP.value.upper(),
                    'lastchg': CONFIGURATION['remove_disconnected_node_after'] * 60,
                },
                False,
            ],
            [
                {
                    'status': ProxyServerState.UP.value.upper(),
                    'lastchg': (CONFIGURATION['remove_disconnected_node_after'] + 1) * 60,
                },
                False,
            ],
            [
                {
                    'status': choice([ProxyServerState.DOWN.value.upper(), ProxyServerState.MAINTENANCE.value.upper()]),
                    'lastchg': (CONFIGURATION['remove_disconnected_node_after'] - 1) * 60,
                },
                False,
            ],
            [
                {
                    'status': choice([ProxyServerState.DOWN.value.upper(), ProxyServerState.MAINTENANCE.value.upper()]),
                    'lastchg': CONFIGURATION['remove_disconnected_node_after'] * 60,
                },
                True,
            ],
            [
                {
                    'status': choice([ProxyServerState.DOWN.value.upper(), ProxyServerState.MAINTENANCE.value.upper()]),
                    'lastchg': (CONFIGURATION['remove_disconnected_node_after'] + 1) * 60,
                },
                True,
            ],
        ),
    )
    async def test_check_node_to_delete(
        self, helper: HAPHelper, proxy_mock: mock.MagicMock, stats: dict, expected: bool
    ):
        """Check the correct output of `check_node_to_delete` method."""
        proxy_mock.get_wazuh_server_stats.return_value = stats
        node_name = 'test_node'

        ret_val = await helper.check_node_to_delete(node_name)

        proxy_mock.get_wazuh_server_stats.assert_called_once_with(server_name=node_name)
        assert ret_val == expected

    async def test_backend_servers_state_healthcheck(self, helper: HAPHelper, proxy_mock: mock.MagicMock):
        """Check that `backend_servers_state_healthcheck` method makes the correct callbacks."""
        WORKER1 = 'worker1'
        WORKER2 = 'worker2'
        BACKEND_DRAIN = {WORKER1: True, WORKER2: False}

        proxy_mock.get_current_backend_servers.return_value = {WORKER1: {}, WORKER2: {}}
        proxy_mock.is_server_drain.side_effect = list(BACKEND_DRAIN.values())

        await helper.backend_servers_state_healthcheck()

        for server in BACKEND_DRAIN.keys():
            proxy_mock.is_server_drain.assert_any_call(server)

        proxy_mock.allow_server_new_connections.assert_called_once_with(WORKER1)

    @pytest.mark.parametrize('check_node_to_delete', [True, False])
    async def test_obtain_nodes_to_configure_servers(
        self, helper: HAPHelper, proxy_mock: mock.MagicMock, dapi_mock: mock.MagicMock, check_node_to_delete: bool
    ):
        """Check the correct output of `obtain_nodes_to_configure` method."""
        WORKER1 = 'worker1'
        WORKER2 = 'worker2'
        WORKER3 = 'worker3'
        WORKER4 = 'worker4'

        expected_add_nodes = [WORKER1, WORKER2]
        expected_remove_nodes = [WORKER2, WORKER4]
        if check_node_to_delete:
            expected_remove_nodes.append(WORKER3)

        wazuh_cluster_nodes = {WORKER1: '192.168.0.1', WORKER2: '192.168.0.2'}
        proxy_backend_servers = {WORKER2: '192.168.0.3', WORKER3: '192.168.0.4', WORKER4: '192.168.0.5'}

        dapi_mock.excluded_nodes = [WORKER4]

        with mock.patch.object(helper, 'check_node_to_delete', return_value=check_node_to_delete) as check_mock:
            add_nodes, remove_nodes = await helper.obtain_nodes_to_configure(wazuh_cluster_nodes, proxy_backend_servers)
            check_mock.assert_called_once_with(WORKER3)

        assert add_nodes == expected_add_nodes
        assert not set(remove_nodes) - set(expected_remove_nodes)

    @pytest.mark.parametrize('agents_count,expected', ([6, 1], [11, 2]))
    @pytest.mark.asyncio
    async def test_update_agent_connections(
        self, helper: HAPHelper, dapi_mock: mock.MagicMock, sleep_mock: mock.AsyncMock, agents_count: int, expected: int
    ):
        """Check that `update_agent_connections` method makes the correct callbacks."""
        agent_list = [f'{n:03}' for n in range(1, agents_count)]

        await helper.update_agent_connections(agent_list)

        assert dapi_mock.reconnect_agents.call_count == expected
        for index in range(0, len(agent_list), helper.agent_reconnection_chunk_size):
            dapi_mock.reconnect_agents.assert_any_call(agent_list[index : index + helper.agent_reconnection_chunk_size])
        assert sleep_mock.call_count == expected

    @pytest.mark.parametrize(
        'agent_list,elegible_agents',
        (
            [
                [
                    {'id': '001', 'version': '4.9.0'},
                    {'id': '002', 'version': '4.9.0'},
                    {'id': '003', 'version': '4.9.0'},
                ],
                ['001', '002', '003'],
            ],
            [
                [
                    {'id': '001', 'version': '4.9.0'},
                    {'id': '002', 'version': '4.9.0'},
                    {'id': '003', 'version': '4.2.0'},
                ],
                ['001', '002'],
            ],
        ),
    )
    async def test_force_agent_reconnection_to_server(
        self,
        wazuh_agent_mock: mock.MagicMock,
        helper: HAPHelper,
        proxy_mock: mock.MagicMock,
        sleep_mock: mock.AsyncMock,
        agent_list: list,
        elegible_agents: list,
    ):
        """Check that `force_agent_reconnection_to_server` method makes the correct callbacks."""
        WORKER1 = 'worker1'
        WORKER2 = 'worker2'
        WORKER3 = 'worker3'

        proxy_mock.get_current_backend_servers.return_value = {
            WORKER1: {},
            WORKER2: {},
            WORKER3: {},
        }
        wazuh_agent_mock.return_value = elegible_agents

        with mock.patch.object(helper, 'update_agent_connections') as update_agent_connections_mock:
            await helper.force_agent_reconnection_to_server(WORKER1, agent_list)
            update_agent_connections_mock.assert_called_once_with(agent_list=elegible_agents)

        for server in [WORKER2, WORKER3]:
            proxy_mock.restrain_server_new_connections.assert_any_call(server)
            proxy_mock.allow_server_new_connections.assert_any_call(server)

        assert sleep_mock.call_count == 2
        sleep_mock.assert_called_with(helper.SERVER_ADMIN_STATE_DELAY)

    async def test_migrate_old_connections(
        self, helper: HAPHelper, proxy_mock: mock.MagicMock, dapi_mock: mock.MagicMock, sleep_mock: mock.AsyncMock
    ):
        """Check that `migrate_old_connections` method makes the correct callbacks."""
        WORKER1 = 'worker1'
        WORKER2 = 'worker2'
        WORKER3 = 'worker3'

        NEW_SERVERS = [WORKER2]
        OLD_SERVERS = [WORKER3]

        AGENTS_TO_FORCE = [{'id': '001', 'version': 'v4.9.0'}]
        AGENTS_TO_UPDATE = [{'id': '002', 'version': 'v4.9.0'}]

        PREVIOUS_CONNECTION_DIST = {WORKER1: 1, WORKER3: 1}

        proxy_mock.get_wazuh_backend_stats.return_value = {WORKER1: {}, WORKER2: {}}
        dapi_mock.get_agents_node_distribution.return_value = {
            WORKER1: AGENTS_TO_FORCE,
            WORKER3: AGENTS_TO_UPDATE,
        }
        proxy_mock.get_wazuh_backend_server_connections.return_value = PREVIOUS_CONNECTION_DIST
        with mock.patch.object(helper, 'check_for_balance', return_value={WORKER3: 1}) as check_for_balance_mock:
            with mock.patch.object(
                helper, 'force_agent_reconnection_to_server'
            ) as force_agent_reconnection_to_server_mock:
                with mock.patch.object(helper, 'update_agent_connections') as update_agent_connections_mock:
                    await helper.migrate_old_connections(NEW_SERVERS, OLD_SERVERS)
                    check_for_balance_mock.assert_called_once_with(
                        current_connections_distribution=PREVIOUS_CONNECTION_DIST
                    )
                    force_agent_reconnection_to_server_mock.assert_called_once_with(
                        chosen_server=WORKER1, agents_list=AGENTS_TO_FORCE
                    )
                    update_agent_connections_mock.assert_called_once_with(
                        agent_list=[item['id'] for item in AGENTS_TO_UPDATE]
                    )
        sleep_mock.assert_any_call(helper.agent_reconnection_stability_time)

    async def test_migrate_old_connections_ko(
        self, helper: HAPHelper, proxy_mock: mock.MagicMock, sleep_mock: mock.AsyncMock
    ):
        """Check that `migrate_old_connections` method makes the correct callbacks."""
        WORKER1 = 'worker1'
        WORKER2 = 'worker2'
        WORKER3 = 'worker3'

        NEW_SERVERS = [WORKER2]
        OLD_SERVERS = [WORKER3]

        proxy_mock.get_wazuh_backend_stats.return_value = {WORKER1: {}}

        with pytest.raises(WazuhHAPHelperError, match='.*3041.*'):
            await helper.migrate_old_connections(NEW_SERVERS, OLD_SERVERS)

        assert sleep_mock.call_count == helper.UPDATED_BACKEND_STATUS_TIMEOUT

    @pytest.mark.parametrize(
        'distribution,expected',
        (
            [{}, {}],
            [{'worker1': 1, 'worker2': 2, 'worker3': 1}, {}],
            [{'worker1': 0, 'worker2': 2, 'worker3': 1}, {'worker2': 1}],
            [{'worker1': 0, 'worker2': 2, 'worker3': 2}, {'worker2': 1, 'worker3': 1}],
            [{'worker1': 0, 'worker2': 4, 'worker3': 0}, {'worker2': 3}],
        ),
    )
    async def test_check_for_balance(self, helper: HAPHelper, distribution: dict, expected: dict):
        """Check the correct output of `check_for_balance` method."""
        assert helper.check_for_balance(current_connections_distribution=distribution) == expected

    @pytest.mark.parametrize(
        'agent_list,elegible_agents',
        (
            [[{'id': '001'}, {'id': '002'}, {'id': '003'}], ['001', '002', '003']],
            [[{'id': '001'}, {'id': '002'}, {'id': '003'}], ['001', '002']],
        ),
    )
    async def test_calculate_agents_to_balance(
        self,
        helper: HAPHelper,
        dapi_mock: mock.MagicMock,
        wazuh_agent_mock: mock.MagicMock,
        agent_list: list,
        elegible_agents: list,
    ):
        """Check the correct output of `calculate_agents_to_balance` method."""
        WORKER1 = 'worker1'

        affected_servers = {WORKER1: 3}
        dapi_mock.get_agents_belonging_to_node.return_value = agent_list
        wazuh_agent_mock.return_value = elegible_agents

        assert (await helper.calculate_agents_to_balance(affected_servers)) == {WORKER1: elegible_agents}
        if len(elegible_agents) != len(agent_list):
            helper.logger.warning.assert_called_once()

    async def test_balance_agents(self, helper: HAPHelper, proxy_mock: mock.MagicMock):
        """Check that `balance_agents` method makes the correct callbacks."""
        WORKER1 = 'worker1'

        affected_servers = {WORKER1: 3}
        agent_list = ['001', '002', '003']
        agents_to_balance = {WORKER1: agent_list}

        with mock.patch.object(
            helper, 'calculate_agents_to_balance', return_value=agents_to_balance
        ) as calculate_agents_to_balance_mock:
            with mock.patch.object(helper, 'update_agent_connections') as update_agent_connections_mock:
                await helper.balance_agents(affected_servers)
                calculate_agents_to_balance_mock.assert_called_once_with(affected_servers)
                update_agent_connections_mock.assert_called_once_with(agent_list=agent_list)

    @pytest.mark.parametrize(
        'nodes_to_add,nodes_to_remove,unbalanced_connections',
        [
            ([], ['worker2'], {}),
            (['worker2'], [], {}),
            (['worker1', 'worker2'], ['worker3'], {}),
            ([], [], {'worker1': 10, 'worker2': 8}),
        ],
    )
    async def test_manage_wazuh_cluster_nodes(
        self,
        helper: HAPHelper,
        proxy_mock: mock.MagicMock,
        dapi_mock: mock.MagicMock,
        sleep_mock: mock.AsyncMock,
        nodes_to_add: list,
        nodes_to_remove: list,
        unbalanced_connections: dict,
    ):
        """Check that `manage_wazuh_cluster_nodes` method makes the correct callbacks."""
        WORKER1 = 'worker1'
        WORKER2 = 'worker2'
        WORKER3 = 'worker3'

        nodes = {WORKER1: '192.168.0.1', WORKER2: '192.168.0.2', WORKER3: '192.168.0.3'}
        nodes_to_configure = [(nodes_to_add, nodes_to_remove)]
        if any([nodes_to_add, nodes_to_remove]):
            nodes_to_configure.append(([], []))

        dapi_mock.get_cluster_nodes.return_value = nodes
        proxy_mock.get_current_backend_servers.return_value = nodes
        proxy_mock.resolver = 'test'

        with mock.patch.object(helper, 'backend_servers_state_healthcheck'):
            with mock.patch.object(helper, 'obtain_nodes_to_configure', side_effect=nodes_to_configure):
                with mock.patch.object(helper, 'set_hard_stop_after'):
                    with mock.patch.object(helper, 'migrate_old_connections'):
                        with mock.patch.object(helper, 'check_for_balance', return_value=unbalanced_connections):
                            with mock.patch.object(helper, 'balance_agents'):
                                try:
                                    await wait_for(helper.manage_wazuh_cluster_nodes(), 0.5)
                                except (TimeoutError, StopAsyncIteration):
                                    pass

                                assert helper.backend_servers_state_healthcheck.call_count

                                if nodes_to_add or nodes_to_remove:
                                    for node_to_remove in nodes_to_remove:
                                        proxy_mock.remove_wazuh_manager.assert_any_call(manager_name=node_to_remove)

                                    for node_to_add in nodes_to_add:
                                        proxy_mock.add_wazuh_manager.assert_any_call(
                                            manager_name=node_to_add,
                                            manager_address=nodes[node_to_add],
                                            resolver=proxy_mock.resolver,
                                        )
                                    helper.set_hard_stop_after.assert_called_once_with(
                                        wait_connection_retry=False, reconnect_agents=False
                                    )
                                    helper.migrate_old_connections.assert_called_once_with(
                                        new_servers=nodes_to_add, deleted_servers=nodes_to_remove
                                    )
                                if unbalanced_connections:
                                    sleep_mock.assert_any_call(helper.AGENT_STATUS_SYNC_TIME)
                                    helper.balance_agents.assert_called_once_with(
                                        affected_servers=unbalanced_connections
                                    )
                                else:
                                    helper.logger.info.assert_any_call('Load balancer backend is balanced')
                                sleep_mock.assert_any_call(helper.sleep_time)

    async def test_manage_wazuh_cluster_nodes_ko(
        self,
        helper: HAPHelper,
        sleep_mock: mock.AsyncMock,
    ):
        """Check the correct error handling of `manage_wazuh_cluster_nodes` method."""
        error = WazuhException(3000, 'Some test exception')

        with mock.patch.object(helper, 'backend_servers_state_healthcheck', side_effect=[error]):
            try:
                await wait_for(helper.manage_wazuh_cluster_nodes(), 0.5)
            except (TimeoutError, StopAsyncIteration):
                pass
            helper.logger.error.assert_called_once_with(str(error))
            sleep_mock.assert_any_call(helper.sleep_time)

    @pytest.mark.parametrize('wait_connection_retry,reconnect_agents', ([True, False], [False, False], [False, True]))
    @pytest.mark.parametrize('agent_ids', (['001', '002'], []))
    async def test_set_hard_stop_after(
        self,
        helper: HAPHelper,
        proxy_mock: mock.MagicMock,
        dapi_mock: mock.MagicMock,
        sleep_mock: mock.AsyncMock,
        wait_connection_retry: bool,
        reconnect_agents: bool,
        agent_ids: list,
    ):
        """Check that `set_hard_stop_after` method makes the correct callbacks."""
        WORKER1 = 'worker1'

        AGENT_NODE_DISTRIBUTION = {WORKER1: [{'id': agent_id} for agent_id in agent_ids]}
        CLUSTER_NODES = {WORKER1: '192.168.0.1'}

        dapi_mock.get_agents_node_distribution.return_value = AGENT_NODE_DISTRIBUTION
        dapi_mock.get_cluster_nodes.return_value = CLUSTER_NODES
        connection_retry = 10
        with mock.patch.object(
            helper, 'get_connection_retry', return_value=connection_retry
        ) as get_connection_retry_mock:
            with mock.patch.object(helper, 'update_agent_connections') as update_agent_connections_mock:
                await helper.set_hard_stop_after(wait_connection_retry, reconnect_agents)

                if wait_connection_retry:
                    get_connection_retry_mock.assert_called_once()
                    sleep_mock.assert_called_once_with(connection_retry)
                else:
                    get_connection_retry_mock.assert_not_called()

                proxy_mock.set_hard_stop_after_value.assert_called_once_with(
                    active_agents=len(agent_ids),
                    chunk_size=helper.agent_reconnection_chunk_size,
                    agent_reconnection_time=helper.agent_reconnection_time,
                    n_managers=len(CLUSTER_NODES.keys()),
                    server_admin_state_delay=helper.SERVER_ADMIN_STATE_DELAY,
                )

                if reconnect_agents and len(agent_ids) > 0:
                    update_agent_connections_mock.assert_called_once_with(agent_list=agent_ids)
                else:
                    update_agent_connections_mock.assert_not_called()

    async def test_get_connection_retry(self, helper: HAPHelper, proxy_mock: mock.MagicMock):
        """Check the correct output of `get_connection_retry` method."""
        CONNECTION_RETRY = 10

        assert helper.get_connection_retry() == CONNECTION_RETRY + 2

    @pytest.mark.skip(reason='This functionality will be removed')
    @pytest.mark.parametrize('protocol', ['http', 'https'])
    @pytest.mark.parametrize('hard_stop_after', [None, 8, 12])
    @pytest.mark.parametrize('multiple_frontends', [True, False])
    async def test_start(
        self,
        proxy_api_mock: mock.MagicMock,
        proxy_mock: mock.MagicMock,
        dapi_mock: mock.MagicMock,
        sleep_mock: mock.AsyncMock,
        protocol: str,
        hard_stop_after: int | None,
        multiple_frontends: bool,
    ):
        """Check that `start` method makes the correct callbacks."""
        HAPROXY_USER_VALUE = 'test'
        HAPROXY_PASSWORD_VALUE = 'test'
        HAPROXY_ADDRESS_VALUE = 'wazuh-proxy'
        HAPROXY_PORT_VALUE = 5555
        HAPROXY_PROTOCOL_VALUE = protocol
        HAPROXY_BACKEND_VALUE = 'wazuh_test'
        HAPROXY_RESOLVER_VALUE = 'resolver_test'
        HAPROXY_CERT_VALUE = 'example_cert.pem' if protocol == 'https' else True
        CLIENT_CERT_VALUE = None
        CLIENT_CERT_KEY_VALUE = None
        CLIENT_CERT_PASSWORD_VALUE = None
        EXCLUDED_NODES_VALUE = ['worker1']
        FREQUENCY_VALUE = 60
        AGENT_RECONNECTION_STABILITY_TIME_VALUE = 10
        AGENT_RECONNECTION_TIME_VALUE = 1
        AGENT_CHUNK_SIZE_VALUE = 10
        IMBALANCE_TOLERANCE_VALUE = 0.1
        REMOVE_DISCONNECTED_NODE_AFTER_VALUE = 3
        WAZUH_PORT = 1514
        TAG = 'HAPHelper'

        HELPER_CONFIG = {
            HAPROXY_USER: HAPROXY_USER_VALUE,
            HAPROXY_PASSWORD: HAPROXY_PASSWORD_VALUE,
            HAPROXY_ADDRESS: HAPROXY_ADDRESS_VALUE,
            HAPROXY_PORT: HAPROXY_PORT_VALUE,
            HAPROXY_PROTOCOL: HAPROXY_PROTOCOL_VALUE,
            HAPROXY_BACKEND: HAPROXY_BACKEND_VALUE,
            HAPROXY_RESOLVER: HAPROXY_RESOLVER_VALUE,
            HAPROXY_CERT: HAPROXY_CERT_VALUE,
            CLIENT_CERT: CLIENT_CERT_VALUE,
            CLIENT_CERT_KEY: CLIENT_CERT_KEY_VALUE,
            CLIENT_CERT_PASSWORD: CLIENT_CERT_PASSWORD_VALUE,
            EXCLUDED_NODES: EXCLUDED_NODES_VALUE,
            FREQUENCY: FREQUENCY_VALUE,
            AGENT_RECONNECTION_STABILITY_TIME: AGENT_RECONNECTION_STABILITY_TIME_VALUE,
            AGENT_RECONNECTION_TIME: AGENT_RECONNECTION_TIME_VALUE,
            AGENT_CHUNK_SIZE: AGENT_CHUNK_SIZE_VALUE,
            IMBALANCE_TOLERANCE: IMBALANCE_TOLERANCE_VALUE,
            REMOVE_DISCONNECTED_NODE_AFTER: REMOVE_DISCONNECTED_NODE_AFTER_VALUE,
        }

        proxy_api = mock.MagicMock()
        proxy_api_mock.return_value = proxy_api

        proxy = mock.MagicMock(hard_stop_after=hard_stop_after, wazuh_backend=HAPROXY_BACKEND_VALUE)
        proxy.check_multiple_frontends = mock.AsyncMock(return_value=multiple_frontends)
        proxy_mock.return_value = proxy

        dapi = mock.MagicMock()
        dapi_mock.return_value = dapi

        logger_mock = mock.MagicMock()

        connection_retry = 10
        with mock.patch.object(HAPHelper, 'initialize_proxy', new=mock.AsyncMock()):
            with mock.patch.object(HAPHelper, 'get_connection_retry', return_value=connection_retry):
                with mock.patch.object(HAPHelper, 'initialize_wazuh_cluster_configuration', new=mock.AsyncMock()):
                    with mock.patch.object(HAPHelper, 'set_hard_stop_after', new=mock.AsyncMock()):
                        with mock.patch.object(HAPHelper, 'manage_wazuh_cluster_nodes', new=mock.AsyncMock()):
                            with mock.patch.object(HAPHelper, '_get_logger', return_value=logger_mock):
                                await HAPHelper.start()

                                proxy_api_mock.assert_called_once_with(
                                    username=HAPROXY_USER_VALUE,
                                    password=HAPROXY_PASSWORD_VALUE,
                                    tag=TAG,
                                    address=HAPROXY_ADDRESS_VALUE,
                                    port=HAPROXY_PORT_VALUE,
                                    protocol=HAPROXY_PROTOCOL_VALUE,
                                    haproxy_cert_file=HAPROXY_CERT_VALUE,
                                    client_cert_file=None,
                                    client_key_file=None,
                                    client_password=None,
                                )

                                proxy_mock.assert_called_once_with(
                                    wazuh_backend=HAPROXY_BACKEND_VALUE,
                                    wazuh_connection_port=WAZUH_PORT,
                                    proxy_api=proxy_api,
                                    tag=TAG,
                                    resolver=HAPROXY_RESOLVER_VALUE,
                                )

                                dapi_mock.assert_called_once_with(tag=TAG, excluded_nodes=EXCLUDED_NODES_VALUE)

                                HAPHelper.initialize_proxy.assert_called_once()

                                proxy.check_multiple_frontends.assert_called_once_with(
                                    port=WAZUH_PORT, frontend_to_skip=f'{HAPROXY_BACKEND_VALUE}_front'
                                )
                                if multiple_frontends and protocol == 'https':
                                    logger_mock.warning.assert_called_once()
                                elif multiple_frontends and protocol == 'http':
                                    assert logger_mock.warning.call_count == 2
                                else:
                                    assert logger_mock.call_count == 0

                                if hard_stop_after is not None:
                                    sleep_mock.assert_called_once_with(max(hard_stop_after, connection_retry))

                                HAPHelper.initialize_wazuh_cluster_configuration.assert_called_once()

                                if hard_stop_after is None:
                                    HAPHelper.set_hard_stop_after.assert_called_once()

                                HAPHelper.manage_wazuh_cluster_nodes.assert_called_once()

    @pytest.mark.parametrize('exception', [KeyError(), KeyboardInterrupt(), WazuhHAPHelperError(3046)])
    async def test_start_ko(self, exception: Exception):
        """Check the correct error handling of `start` method."""
        logger_mock = mock.MagicMock()
        with mock.patch.object(HAPHelper, '_get_logger', return_value=logger_mock):
            await HAPHelper.start()
            logger_mock.info.assert_called_once_with('Task ended')
