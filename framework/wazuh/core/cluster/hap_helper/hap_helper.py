import logging
import time
from asyncio import sleep
from math import ceil, floor

from wazuh.core.cluster.hap_helper.configuration import parse_configuration
from wazuh.core.cluster.hap_helper.exception import HAPHelperError, ProxyError, WazuhError
from wazuh.core.cluster.hap_helper.proxy import Proxy, ProxyAPI, ProxyServerState
from wazuh.core.cluster.hap_helper.wazuh import WazuhAgent, WazuhAPI
from wazuh.core.cluster.utils import ClusterFilter


class HAPHelper:
    UPDATED_BACKEND_STATUS_TIMEOUT: int = 60
    AGENT_STATUS_SYNC_TIME: int = 25  # Default agent notify time + cluster sync + 5s
    SERVER_ADMIN_STATE_DELAY: int = 5

    def __init__(self, proxy: Proxy, wazuh_api: WazuhAPI, options: dict):
        self.logger = self._get_logger()
        self.proxy = proxy
        self.wazuh_api = wazuh_api

        self.sleep_time: int = options['sleep_time']
        self.agent_reconnection_stability_time: int = options['agent_reconnection_stability_time']
        self.agent_reconnection_chunk_size: int = options['agent_reconnection_chunk_size']
        self.agent_reconnection_time: int = options['agent_reconnection_time']
        self.agent_tolerance: float = options['agent_tolerance']
        self.remove_disconnected_node_after: int = options['remove_disconnected_node_after']

    @staticmethod
    def _get_logger() -> logging.Logger:
        logger = logging.getLogger('wazuh').getChild('HAPHelper')
        logger.addFilter(ClusterFilter(tag='Cluster', subtag='HAPHelper Main'))

        return logger

    async def initialize_components(self):
        try:
            # self.wazuh_api.initialize()
            await self.proxy.initialize()
            self.logger.info('Main components were initialized')
        except (WazuhError, ProxyError) as init_exc:
            self.logger.critical('Cannot initialize main components')
            self.logger.critical(init_exc)
            exit(1)

    async def initialize_wazuh_cluster_configuration(self):
        if not await self.proxy.exists_backend(self.proxy.wazuh_backend):
            self.logger.info(f"Could not find Wazuh backend '{self.proxy.wazuh_backend}'")
            await self.proxy.add_new_backend(name=self.proxy.wazuh_backend)
            self.logger.info('Added Wazuh backend')

        if not await self.proxy.exists_frontend(f'{self.proxy.wazuh_backend}_front'):
            self.logger.info(f"Could not find Wazuh frontend '{self.proxy.wazuh_backend}_front'")
            await self.proxy.add_new_frontend(
                name=f'{self.proxy.wazuh_backend}_front',
                port=self.proxy.wazuh_connection_port,
                backend=self.proxy.wazuh_backend,
            )
            self.logger.info('Added Wazuh frontend')

    async def check_node_to_delete(self, node_name: str) -> bool:
        node_downtime = (await self.proxy.get_wazuh_server_stats(server_name=node_name))['lastchg']
        self.logger.debug2(f"Server '{node_name}' has been disconnected for {node_downtime}s")

        if node_downtime < self.remove_disconnected_node_after * 60:
            self.logger.info(f"Server '{node_name}' has not been disconnected enough time to remove it")
            return False
        self.logger.info(
            f"Server '{node_name}' has been disconnected for over {self.remove_disconnected_node_after} " 'minutes'
        )
        return True

    # TODO: This must be deprecated
    async def check_proxy_processes(self, auto_mode: bool = False, warn: bool = True) -> bool:
        if not await self.proxy.is_proxy_process_single():
            warn and self.logger.warning('Detected more than one Proxy processes')
            if not auto_mode and input('  Do you wish to fix them? (y/N): ').lower() != 'y':
                return False
            await self.manage_proxy_processes()
            return True

    async def backend_servers_state_healthcheck(self):
        for server in (await self.proxy.get_current_backend_servers()).keys():
            if await self.proxy.is_server_drain(server_name=server):
                self.logger.warning(f"Server '{server}' was found {ProxyServerState.DRAIN.value.upper()}. Fixing it")
                await self.proxy.allow_server_new_connections(server_name=server)

    async def obtain_nodes_to_configure(
        self, wazuh_cluster_nodes: dict, proxy_backend_servers: dict
    ) -> tuple[list, list]:
        add_nodes, remove_nodes = [], []

        for node_name, node_address in wazuh_cluster_nodes.items():
            if node_name not in proxy_backend_servers:
                add_nodes.append(node_name)
            elif node_address != proxy_backend_servers[node_name]:
                remove_nodes.append(node_name)
                add_nodes.append(node_name)
        for node_name in proxy_backend_servers.keys() - wazuh_cluster_nodes.keys():
            if node_name in self.wazuh_api.excluded_nodes:
                self.logger.info(f"Server '{node_name}' has been excluded but is currently active. Removing it")
            elif await self.check_node_to_delete(node_name):
                pass
            else:
                continue
            remove_nodes.append(node_name)

        return add_nodes, remove_nodes

    async def update_agent_connections(self, agent_list: list[str]):
        self.logger.debug('Reconnecting agents')
        self.logger.debug(
            f'Agent reconnection chunk size is set to {self.agent_reconnection_chunk_size}. '
            f'Total iterations: {ceil(len(agent_list) / self.agent_reconnection_chunk_size)}'
        )
        for index in range(0, len(agent_list), self.agent_reconnection_chunk_size):
            await self.wazuh_api.reconnect_agents(agent_list[index : index + self.agent_reconnection_chunk_size])
            self.logger.debug(f'Delay between agent reconnections. Sleeping {self.agent_reconnection_time}s...')
            await sleep(self.agent_reconnection_time)

    async def force_agent_reconnection_to_server(self, chosen_server: str, agents_list: list[dict]):
        current_servers = (await self.proxy.get_current_backend_servers()).keys()
        affected_servers = current_servers - {chosen_server}
        for server_name in affected_servers:
            await self.proxy.restrain_server_new_connections(server_name=server_name)
        await sleep(self.SERVER_ADMIN_STATE_DELAY)
        eligible_agents = WazuhAgent.get_agents_able_to_reconnect(agents_list=agents_list)
        if len(eligible_agents) != len(agents_list):
            self.logger.warning(
                f"Some agents from '{chosen_server}' are not compatible with the reconnection endpoint."
                ' Those connections will be balanced afterwards'
            )
        await self.update_agent_connections(agent_list=eligible_agents)
        for server_name in affected_servers:
            await self.proxy.allow_server_new_connections(server_name=server_name)
        await sleep(self.SERVER_ADMIN_STATE_DELAY)

    # TODO: This must be deprecated
    async def manage_proxy_processes(self):
        current_proxy_pid = (await self.proxy.api.get_runtime_info())['pid']
        response = await self.proxy.api.kill_proxy_processes(pid_to_exclude=current_proxy_pid)

        if response['error'] > 0:
            self.logger.error("Could not manage all proxy processes: " f"{response['data']}")
        elif len(response['data']) > 0:
            self.logger.info('Managed proxy processes')

    async def migrate_old_connections(self, new_servers: list[str], deleted_servers: list[str]):
        wazuh_backend_stats = {}
        backend_stats_iteration = 1
        while any([server not in wazuh_backend_stats for server in new_servers]):
            if backend_stats_iteration > self.UPDATED_BACKEND_STATUS_TIMEOUT:
                self.logger.error(f'Some of the new servers did not go UP: {set(new_servers) - wazuh_backend_stats}')
                raise HAPHelperError(100)

            self.logger.debug('Waiting for new servers to go UP')
            time.sleep(1)
            backend_stats_iteration += 1
            wazuh_backend_stats = (await self.proxy.get_wazuh_backend_stats()).keys()

        self.logger.debug('All new servers are UP')
        previous_agent_distribution = await self.wazuh_api.get_agents_node_distribution()
        previous_connection_distribution = await self.proxy.get_wazuh_backend_server_connections() | {
            server: len(previous_agent_distribution[server])
            for server in previous_agent_distribution
            if server not in new_servers
        }

        unbalanced_connections = self.check_for_balance(
            current_connections_distribution=previous_connection_distribution
        )
        agents_to_balance = []

        for wazuh_worker, agents in previous_agent_distribution.items():
            if wazuh_worker in deleted_servers:
                agents_to_balance += [agent['id'] for agent in agents]
                continue
            try:
                agents_to_balance += [agent['id'] for agent in agents[: unbalanced_connections[wazuh_worker]]]
                agents = agents[unbalanced_connections[wazuh_worker] :]
            except KeyError:
                pass

            self.logger.info(f"Migrating {len(agents)} connections from server '{wazuh_worker}'")
            await self.force_agent_reconnection_to_server(chosen_server=wazuh_worker, agents_list=agents)

        if agents_to_balance:
            self.logger.info('Balancing exceeding connections after changes on the Wazuh backend')
            await self.update_agent_connections(agent_list=agents_to_balance)

        await self.check_proxy_processes(auto_mode=True, warn=False)

        self.logger.info('Waiting for agent connections stability')
        self.logger.debug(f'Sleeping {self.agent_reconnection_stability_time}s...')
        await sleep(self.agent_reconnection_stability_time)

    def check_for_balance(self, current_connections_distribution: dict) -> dict:
        if not current_connections_distribution:
            self.logger.debug('There are not connections at the moment')
            return {}
        self.logger.debug(
            'Checking for agent balance. Current connections distribution: ' f'{current_connections_distribution}'
        )

        total_agents = sum(current_connections_distribution.values())
        try:
            mean = floor(total_agents / len(current_connections_distribution.keys()))
        except ZeroDivisionError:
            return {}

        if (
            max(current_connections_distribution.values()) <= mean * (1 + self.agent_tolerance)
            and min(current_connections_distribution.values()) >= mean * (1 - self.agent_tolerance)
        ) or (
            max(current_connections_distribution.values()) - min(current_connections_distribution.values()) <= 1
            and total_agents % len(current_connections_distribution.keys()) != 0
        ):
            self.logger.debug('Current balance is under tolerance')
            return {}

        unbalanced_connections = {}
        for server, connections in current_connections_distribution.items():
            exceeding_connections = connections - mean
            if exceeding_connections > 0:
                unbalanced_connections[server] = exceeding_connections

        return unbalanced_connections

    async def calculate_agents_to_balance(self, affected_servers: dict) -> dict:
        agents_to_balance = {}
        for server_name, n_agents in affected_servers.items():
            agent_candidates = await self.wazuh_api.get_agents_belonging_to_node(node_name=server_name, limit=n_agents)
            eligible_agents = WazuhAgent.get_agents_able_to_reconnect(agents_list=agent_candidates)
            if len(eligible_agents) != len(agent_candidates):
                self.logger.warning(
                    f'Some agents from node {server_name} are not compatible with the reconnection '
                    'endpoint. Balance might not be precise'
                )
            agents_to_balance[server_name] = eligible_agents

        return agents_to_balance

    async def balance_agents(self, affected_servers: dict):
        self.logger.info('Attempting to balance agent connections')
        agents_to_balance = await self.calculate_agents_to_balance(affected_servers)
        for node_name, agent_ids in agents_to_balance.items():
            self.logger.info(f"Balancing {len(agent_ids)} agents from '{node_name}'")
            await self.update_agent_connections(agent_list=agent_ids)

    async def manage_wazuh_cluster_nodes(self):
        while True:
            try:
                await self.backend_servers_state_healthcheck()
                await self.check_proxy_processes(auto_mode=True) and await sleep(self.AGENT_STATUS_SYNC_TIME)
                current_wazuh_cluster = await self.wazuh_api.get_cluster_nodes()
                current_proxy_backend = await self.proxy.get_current_backend_servers()

                nodes_to_add, nodes_to_remove = await self.obtain_nodes_to_configure(
                    current_wazuh_cluster, current_proxy_backend
                )
                if nodes_to_add or nodes_to_remove:
                    self.logger.info(
                        'Detected changes in Wazuh cluster nodes. Current cluster: ' f'{current_wazuh_cluster}'
                    )
                    self.logger.info('Attempting to update proxy backend')

                    for node_to_remove in nodes_to_remove:
                        await self.proxy.remove_wazuh_manager(manager_name=node_to_remove)

                    for node_to_add in nodes_to_add:
                        await self.proxy.add_wazuh_manager(
                            manager_name=node_to_add,
                            manager_address=current_wazuh_cluster[node_to_add],
                            resolver=self.proxy.resolver,
                        )
                    await self.migrate_old_connections(new_servers=nodes_to_add, deleted_servers=nodes_to_remove)
                    continue

                self.logger.info('Load balancer backend is up to date')
                unbalanced_connections = self.check_for_balance(
                    current_connections_distribution=await self.proxy.get_wazuh_backend_server_connections()
                )
                if not unbalanced_connections:
                    self.logger.debug(
                        'Current backend stats: ' f'{await self.proxy.get_wazuh_backend_server_connections()}'
                    )
                    self.logger.info('Load balancer backend is balanced')
                else:
                    self.logger.info('Agent imbalance detected. Waiting for agent status sync...')
                    await sleep(self.AGENT_STATUS_SYNC_TIME)
                    await self.balance_agents(affected_servers=unbalanced_connections)

                self.logger.debug(f'Sleeping {self.sleep_time}s...')
                await sleep(self.sleep_time)
            except (HAPHelperError, ProxyError, WazuhError) as handled_exc:
                self.logger.error(str(handled_exc))
                self.logger.warning(
                    f'Tasks may not perform as expected. Sleeping {self.sleep_time}s ' 'before continuing...'
                )
                await sleep(self.sleep_time)

    @classmethod
    async def run(cls):
        try:
            configuration = parse_configuration()

            proxy_api = ProxyAPI(
                username=configuration['proxy']['api']['user'],
                password=configuration['proxy']['api']['password'],
                address=configuration['proxy']['api']['address'],
                port=configuration['proxy']['api']['port'],
            )
            proxy = Proxy(
                wazuh_backend=configuration['proxy']['backend'],
                wazuh_connection_port=configuration['wazuh']['connection']['port'],
                proxy_api=proxy_api,
                resolver=configuration['proxy'].get('resolver', None),
            )

            wazuh_api = WazuhAPI(
                address=configuration['wazuh']['api']['address'],
                port=configuration['wazuh']['api']['port'],
                username=configuration['wazuh']['api']['user'],
                password=configuration['wazuh']['api']['password'],
                excluded_nodes=configuration['wazuh']['excluded_nodes'],
            )

            helper = cls(proxy=proxy, wazuh_api=wazuh_api, options=configuration['hap_helper'])

            await helper.initialize_components()
            await helper.initialize_wazuh_cluster_configuration()

            helper.logger.info('Starting HAProxy Helper on auto mode')
            await helper.manage_wazuh_cluster_nodes()
        except (HAPHelperError, ProxyError) as main_exc:
            helper.logger.error(str(main_exc))
        except KeyboardInterrupt:
            pass
        except Exception as unexpected_exc:
            helper.logger.critical(f'Unexpected exception: {unexpected_exc}', exc_info=True)
        finally:
            helper.logger.info('Process ended')
