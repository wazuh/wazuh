import argparse
import logging
import time
from math import ceil, floor

from wazuh_coordinator.configuration import parse_configuration
from wazuh_coordinator.custom_logging import CustomLogger
from wazuh_coordinator.exception import CoordinatorError, ProxyError, WazuhError
from wazuh_coordinator.process import run_in_background
from wazuh_coordinator.proxy import Proxy, ProxyAPI, ProxyServerState
from wazuh_coordinator.wazuh import WazuhAgent, WazuhAPI


class Coordinator:
    UPDATED_BACKEND_STATUS_TIMEOUT: int = 60
    AGENT_STATUS_SYNC_TIME: int = 25  # Default agent notify time + cluster sync + 5s
    SERVER_ADMIN_STATE_DELAY: int = 5

    def __init__(self, proxy: Proxy, wazuh_api: WazuhAPI, logger: logging.Logger, options: dict):
        self.logger = logger
        self.proxy = proxy
        self.wazuh_api = wazuh_api

        self.sleep_time: int = options['sleep_time']
        self.agent_reconnection_stability_time: int = options['agent_reconnection_stability_time']
        self.agent_reconnection_chunk_size: int = options['agent_reconnection_chunk_size']
        self.agent_reconnection_time: int = options['agent_reconnection_time']
        self.agent_tolerance: float = options['agent_tolerance']
        self.remove_disconnected_node_after: int = options['remove_disconnected_node_after']

    def initialize_components(self):
        try:
            self.wazuh_api.initialize()
            self.proxy.initialize()
            self.logger.info('Main components were initialized')
        except (WazuhError, ProxyError) as init_exc:
            self.logger.critical('Cannot initialize main components')
            self.logger.critical(init_exc)
            exit(1)

    def initialize_wazuh_cluster_configuration(self):
        if not self.proxy.exists_backend(self.proxy.wazuh_backend):
            self.logger.info(f"Could not find Wazuh backend '{self.proxy.wazuh_backend}'")
            self.proxy.add_new_backend(name=self.proxy.wazuh_backend)
            self.logger.info('Added Wazuh backend')

        if not self.proxy.exists_frontend(f'{self.proxy.wazuh_backend}_front'):
            self.logger.info(f"Could not find Wazuh frontend '{self.proxy.wazuh_backend}_front'")
            self.proxy.add_new_frontend(
                name=f'{self.proxy.wazuh_backend}_front',
                port=self.proxy.wazuh_connection_port,
                backend=self.proxy.wazuh_backend,
            )
            self.logger.info('Added Wazuh frontend')

    def check_node_to_delete(self, node_name: str) -> bool:
        node_downtime = self.proxy.get_wazuh_server_stats(server_name=node_name)['lastchg']
        self.logger.trace(f"Server '{node_name}' has been disconnected for {node_downtime}s")

        if node_downtime < self.remove_disconnected_node_after * 60:
            self.logger.info(f"Server '{node_name}' has not been disconnected enough time to remove it")
            return False
        self.logger.info(
            f"Server '{node_name}' has been disconnected for over {self.remove_disconnected_node_after} " 'minutes'
        )
        return True

    def check_proxy_processes(self, auto_mode: bool = False, warn: bool = True) -> bool:
        if not self.proxy.is_proxy_process_single():
            warn and self.logger.warning('Detected more than one Proxy processes')
            if not auto_mode and input('  Do you wish to fix them? (y/N): ').lower() != 'y':
                return False
            self.manage_proxy_processes()
            return True

    def backend_servers_state_healthcheck(self):
        for server in self.proxy.get_current_backend_servers().keys():
            if self.proxy.is_server_drain(server_name=server):
                self.logger.warning(f"Server '{server}' was found {ProxyServerState.DRAIN.value.upper()}. Fixing it")
                self.proxy.allow_server_new_connections(server_name=server)

    def obtain_nodes_to_configure(self, wazuh_cluster_nodes: dict, proxy_backend_servers: dict) -> tuple[list, list]:
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
            elif self.check_node_to_delete(node_name):
                pass
            else:
                continue
            remove_nodes.append(node_name)

        return add_nodes, remove_nodes

    def update_agent_connections(self, agent_list: list[str]):
        self.logger.debug('Reconnecting agents')
        self.logger.debug(
            f'Agent reconnection chunk size is set to {self.agent_reconnection_chunk_size}. '
            f'Total iterations: {ceil(len(agent_list) / self.agent_reconnection_chunk_size)}'
        )
        for index in range(0, len(agent_list), self.agent_reconnection_chunk_size):
            self.wazuh_api.reconnect_agents(agent_list[index : index + self.agent_reconnection_chunk_size])
            self.logger.debug(f'Delay between agent reconnections. Sleeping {self.agent_reconnection_time}s...')
            time.sleep(self.agent_reconnection_time)

    def force_agent_reconnection_to_server(self, chosen_server: str, agents_list: list[dict]):
        current_servers = self.proxy.get_current_backend_servers().keys()
        affected_servers = current_servers - {chosen_server}
        for server_name in affected_servers:
            self.proxy.restrain_server_new_connections(server_name=server_name)
        time.sleep(self.SERVER_ADMIN_STATE_DELAY)
        eligible_agents = WazuhAgent.get_agents_able_to_reconnect(agents_list=agents_list)
        if len(eligible_agents) != len(agents_list):
            self.logger.warning(
                f"Some agents from '{chosen_server}' are not compatible with the reconnection endpoint."
                ' Those connections will be balanced afterwards'
            )
        self.update_agent_connections(agent_list=eligible_agents)
        for server_name in affected_servers:
            self.proxy.allow_server_new_connections(server_name=server_name)
        time.sleep(self.SERVER_ADMIN_STATE_DELAY)

    def manage_proxy_processes(self):
        current_proxy_pid = self.proxy.api.get_runtime_info()['pid']
        response = self.proxy.api.kill_proxy_processes(pid_to_exclude=current_proxy_pid)

        if response['error'] > 0:
            self.logger.error("Could not manage all proxy processes: " f"{response['data']}")
        elif len(response['data']) > 0:
            self.logger.info('Managed proxy processes')

    def migrate_old_connections(self, new_servers: list[str], deleted_servers: list[str]):
        wazuh_backend_stats = {}
        backend_stats_iteration = 1
        while any([server not in wazuh_backend_stats for server in new_servers]):
            if backend_stats_iteration > self.UPDATED_BACKEND_STATUS_TIMEOUT:
                self.logger.error(f'Some of the new servers did not go UP: {set(new_servers) - wazuh_backend_stats}')
                raise CoordinatorError(100)

            self.logger.debug('Waiting for new servers to go UP')
            time.sleep(1)
            backend_stats_iteration += 1
            wazuh_backend_stats = self.proxy.get_wazuh_backend_stats().keys()

        self.logger.debug('All new servers are UP')
        previous_agent_distribution = self.wazuh_api.get_agents_node_distribution()
        previous_connection_distribution = self.proxy.get_wazuh_backend_server_connections() | {
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
            self.force_agent_reconnection_to_server(chosen_server=wazuh_worker, agents_list=agents)

        if agents_to_balance:
            self.logger.info('Balancing exceeding connections after changes on the Wazuh backend')
            self.update_agent_connections(agent_list=agents_to_balance)

        self.check_proxy_processes(auto_mode=True, warn=False)

        self.logger.info('Waiting for agent connections stability')
        self.logger.debug(f'Sleeping {self.agent_reconnection_stability_time}s...')
        time.sleep(self.agent_reconnection_stability_time)

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

    def calculate_agents_to_balance(self, affected_servers: dict) -> dict:
        agents_to_balance = {}
        for server_name, n_agents in affected_servers.items():
            agent_candidates = self.wazuh_api.get_agents_belonging_to_node(node_name=server_name, limit=n_agents)
            eligible_agents = WazuhAgent.get_agents_able_to_reconnect(agents_list=agent_candidates)
            if len(eligible_agents) != len(agent_candidates):
                self.logger.warning(
                    f'Some agents from node {server_name} are not compatible with the reconnection '
                    'endpoint. Balance might not be precise'
                )
            agents_to_balance[server_name] = eligible_agents

        return agents_to_balance

    def balance_agents(self, affected_servers: dict):
        self.logger.info('Attempting to balance agent connections')
        agents_to_balance = self.calculate_agents_to_balance(affected_servers)
        for node_name, agent_ids in agents_to_balance.items():
            self.logger.info(f"Balancing {len(agent_ids)} agents from '{node_name}'")
            self.update_agent_connections(agent_list=agent_ids)

    def manage_wazuh_cluster_nodes(self):
        while True:
            try:
                self.backend_servers_state_healthcheck()
                self.check_proxy_processes(auto_mode=True) and time.sleep(self.AGENT_STATUS_SYNC_TIME)
                current_wazuh_cluster = self.wazuh_api.get_cluster_nodes()
                current_proxy_backend = self.proxy.get_current_backend_servers()

                nodes_to_add, nodes_to_remove = self.obtain_nodes_to_configure(
                    current_wazuh_cluster, current_proxy_backend
                )
                if nodes_to_add or nodes_to_remove:
                    self.logger.info(
                        'Detected changes in Wazuh cluster nodes. Current cluster: ' f'{current_wazuh_cluster}'
                    )
                    self.logger.info('Attempting to update proxy backend')

                    for node_to_remove in nodes_to_remove:
                        self.proxy.remove_wazuh_manager(manager_name=node_to_remove)

                    for node_to_add in nodes_to_add:
                        self.proxy.add_wazuh_manager(
                            manager_name=node_to_add,
                            manager_address=current_wazuh_cluster[node_to_add],
                            resolver=self.proxy.resolver,
                        )
                    self.migrate_old_connections(new_servers=nodes_to_add, deleted_servers=nodes_to_remove)
                    continue

                self.logger.info('Load balancer backend is up to date')
                unbalanced_connections = self.check_for_balance(
                    current_connections_distribution=self.proxy.get_wazuh_backend_server_connections()
                )
                if not unbalanced_connections:
                    if self.logger.level <= logging.DEBUG:
                        self.logger.debug(
                            'Current backend stats: ' f'{self.proxy.get_wazuh_backend_server_connections()}'
                        )
                    self.logger.info('Load balancer backend is balanced')
                else:
                    self.logger.info('Agent imbalance detected. Waiting for agent status sync...')
                    time.sleep(self.AGENT_STATUS_SYNC_TIME)
                    self.balance_agents(affected_servers=unbalanced_connections)

                self.logger.debug(f'Sleeping {self.sleep_time}s...')
                time.sleep(self.sleep_time)
            except (CoordinatorError, ProxyError, WazuhError) as handled_exc:
                self.logger.error(str(handled_exc))
                self.logger.warning(
                    f'Tasks may not perform as expected. Sleeping {self.sleep_time}s ' 'before continuing...'
                )
                time.sleep(self.sleep_time)


def setup_loggers(log_file_path: str, log_level: int) -> tuple[logging.Logger, logging.Logger, logging.Logger]:
    main_logger = CustomLogger('wazuh-coordinator', file_path=log_file_path, level=log_level).get_logger()
    proxy_logger = CustomLogger('proxy-logger', file_path=log_file_path, level=log_level, tag='Proxy').get_logger()
    wazuh_api_logger = CustomLogger(
        'wazuh-api-logger', file_path=log_file_path, level=log_level, tag='Wazuh API'
    ).get_logger()

    return main_logger, proxy_logger, wazuh_api_logger


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Wazuh coordinator')
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '--auto',
        dest='auto',
        action='store_true',
        help='Run coordinator capabilities on auto mode (full functionality)',
    )
    group.add_argument(
        '-a',
        '--add-server',
        dest='add_server',
        action='store',
        type=str,
        nargs=2,
        metavar=('SERVER_NAME', 'SERVER_ADDRESS'),
        help='Add a new server to configured backend',
    )
    group.add_argument(
        '-r',
        '--remove-server',
        dest='remove_server',
        action='store',
        type=str,
        metavar='SERVER_NAME',
        help='Remove server from configured backend',
    )
    group.add_argument(
        '-cb',
        '--check-balance',
        dest='check_for_balance',
        action='store_true',
        help='Check if the environment needs to be balanced',
    )
    parser.add_argument(
        '-c',
        '--configuration-file',
        dest='configuration_file',
        action='store',
        default='',
        help='Path to the test result file',
    )
    parser.add_argument('-l', '--log-file', dest='log_file', action='store', help='Path to the logging file')
    parser.add_argument(
        '-b', '--background', dest='background', action='store_true', help='Run coordinator on background'
    )
    parser.add_argument(
        '-d',
        '--debug',
        dest='log_debug',
        action='store',
        type=str,
        choices=['debug', 'trace'],
        help='Enable debug logging',
    )

    return parser.parse_args()


def main():
    arguments = parse_arguments()

    user_config_path = arguments.configuration_file
    log_file = arguments.log_file
    log_level = (
        CustomLogger.TRACE_LEVEL
        if arguments.log_debug == 'trace'
        else logging.DEBUG
        if arguments.log_debug == 'debug'
        else logging.INFO
    )

    if arguments.background:
        run_in_background()

    main_logger, proxy_logger, wazuh_api_logger = setup_loggers(log_file_path=log_file, log_level=log_level)

    try:
        configuration = parse_configuration(custom_configuration_path=user_config_path)
        resolver = configuration['proxy'].get('resolver', None)

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
            logger=proxy_logger,
            resolver=resolver,
        )

        wazuh_api = WazuhAPI(
            address=configuration['wazuh']['api']['address'],
            port=configuration['wazuh']['api']['port'],
            username=configuration['wazuh']['api']['user'],
            password=configuration['wazuh']['api']['password'],
            excluded_nodes=configuration['wazuh']['excluded_nodes'],
            logger=wazuh_api_logger,
        )

        coordinator = Coordinator(
            proxy=proxy, wazuh_api=wazuh_api, logger=main_logger, options=configuration['coordinator']
        )

        coordinator.initialize_components()
        coordinator.initialize_wazuh_cluster_configuration()
        if arguments.auto:
            main_logger.info('Starting coordinator on auto mode')
            coordinator.manage_wazuh_cluster_nodes()
        elif arguments.add_server:
            server_name, server_address = arguments.add_server
            coordinator.backend_servers_state_healthcheck()
            proxy.add_wazuh_manager(manager_name=server_name, manager_address=server_address, resolver=resolver)
            main_logger.info(f"Server '{server_name}' was successfully added")
            main_logger.info(f'Attempting to migrate connections')
            coordinator.migrate_old_connections(new_servers=[server_name], deleted_servers=[])
        elif arguments.remove_server:
            server_name = arguments.remove_server
            coordinator.backend_servers_state_healthcheck()
            proxy.remove_wazuh_manager(manager_name=server_name)
            main_logger.info(f"Server '{server_name}' was successfully removed")
            main_logger.info(f'Attempting to migrate connections')
            coordinator.migrate_old_connections(new_servers=[], deleted_servers=[server_name])
        elif arguments.check_for_balance:
            if coordinator.check_proxy_processes():
                main_logger.info(f'Sleeping {coordinator.AGENT_STATUS_SYNC_TIME}s before continuing...')
                time.sleep(coordinator.AGENT_STATUS_SYNC_TIME)
            unbalanced_connections = coordinator.check_for_balance(
                current_connections_distribution=proxy.get_wazuh_backend_server_connections()
            )
            if not unbalanced_connections:
                main_logger.info('Load balancer backend is balanced')
                exit(0)
            main_logger.info(f'Agent imbalance detected. Surplus agents per node: {unbalanced_connections}')
            if input('  Do you wish to balance agents? (y/N): ').lower() == 'y':
                coordinator.balance_agents(affected_servers=unbalanced_connections)
    except (CoordinatorError, ProxyError) as main_exc:
        main_logger.error(str(main_exc))
    except KeyboardInterrupt:
        pass
    except Exception as unexpected_exc:
        main_logger.critical(f'Unexpected exception: {unexpected_exc}', exc_info=True)
    finally:
        main_logger.info('Process ended')


if __name__ == '__main__':
    main()
