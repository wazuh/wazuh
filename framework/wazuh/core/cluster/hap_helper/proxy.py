import logging
import ipaddress
from enum import Enum
from typing import TypeAlias, Optional

import requests
from wazuh_coordinator.exception import ProxyError

JSON_TYPE: TypeAlias = dict | list[dict]
PROXY_API_RESPONSE: TypeAlias = JSON_TYPE


class ProxyAPIMethod(Enum):
    GET = 'get'
    POST = 'post'
    PUT = 'put'
    DELETE = 'delete'


class ProxyServerState(Enum):
    READY = 'ready'
    MAINTENANCE = 'maint'
    DRAIN = 'drain'


class CommunicationProtocol(Enum):
    TCP = 'tcp'
    HTTP = 'http'


class ProxyBalanceAlgorithm(Enum):
    ROUND_ROBIN = 'roundrobin'
    LEAST_CONNECTIONS = 'leastconn'


class ProxyAPI:
    HAPEE_ENDPOINT = '/hapee'

    def __init__(self, username: str, password: str, address: str = 'localhost', port: int = 7777):
        self.username = username
        self.password = password
        self.address = address
        self.port = port

        self.version = 0

    def initialize(self):
        try:
            response = requests.post(
                f'https://{self.address}:{self.port}/', auth=(self.username, self.password), verify=False
            )
            if response.status_code == 401:
                raise ProxyError(102)
            elif response.status_code == 404:
                raise ProxyError(103)
        except requests.ConnectionError:
            raise ProxyError(99, extra_msg='Check connectivity and the configuration file')
        except requests.RequestException as req_exc:
            raise ProxyError(99, extra_msg=str(req_exc))

    def _make_hapee_request(
        self,
        endpoint: str,
        method: ProxyAPIMethod = ProxyAPIMethod.GET,
        query_parameters: dict | None = None,
        json_body: dict | None = None,
    ) -> PROXY_API_RESPONSE:
        uri = f'https://{self.address}:{self.port}{self.HAPEE_ENDPOINT}'
        query_parameters = query_parameters or {}
        query_parameters.update({'version': self.version})

        hapee_json_body = {
            'method': method.value,
            'uri': endpoint,
            'query_parameters': query_parameters,
            'json_body': json_body or {},
        }

        try:
            response = requests.post(uri, auth=(self.username, self.password), json=hapee_json_body, verify=False)
        except requests.RequestException as request_exc:
            raise ProxyError(100, extra_msg=str(request_exc))

        if response.status_code == 200:
            full_decoded_response = response.json()
            decoded_response = full_decoded_response['data']['response']
            if full_decoded_response['error'] != 0:
                raise ProxyError(105, extra_msg=f'Full response: {response.status_code} | {response.json()}')
            if isinstance(decoded_response, dict) and '_version' in decoded_response:
                self.version = decoded_response['_version']
            elif method != ProxyAPIMethod.GET and 'configuration' in endpoint:
                self.update_configuration_version()

            return decoded_response
        elif response.status_code == 401:
            raise ProxyError(102)
        else:
            raise ProxyError(101, extra_msg=f'Full response: {response.status_code} | {response.json()}')

    def _make_proxy_request(
        self,
        endpoint: str,
        method: ProxyAPIMethod = ProxyAPIMethod.GET,
        query_parameters: dict | None = None,
        json_body: dict | None = None,
    ) -> PROXY_API_RESPONSE:
        uri = f'https://{self.address}:{self.port}{endpoint}'

        try:
            response = getattr(requests, str(method.value))(
                uri, auth=(self.username, self.password), params=query_parameters, json=json_body, verify=False
            )
        except requests.RequestException as request_exc:
            raise ProxyError(100, extra_msg=str(request_exc))

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            raise ProxyError(102)
        else:
            raise ProxyError(101, extra_msg=f'Full response: {response.status_code} | {response.json()}')

    def update_configuration_version(self):
        configuration_version = self._make_hapee_request('/services/haproxy/configuration/version')
        self.version = configuration_version

    def get_runtime_info(self) -> PROXY_API_RESPONSE:
        return self._make_hapee_request('/services/haproxy/runtime/info')[0]['info']

    def get_backends(self) -> PROXY_API_RESPONSE:
        return self._make_hapee_request(endpoint='/services/haproxy/configuration/backends')

    def add_backend(
        self,
        name: str,
        mode: CommunicationProtocol = CommunicationProtocol.TCP,
        algorithm: ProxyBalanceAlgorithm = ProxyBalanceAlgorithm.LEAST_CONNECTIONS,
    ) -> PROXY_API_RESPONSE:
        query_params = {'force_reload': True}
        json_body = {'name': name, 'mode': mode.value, 'balance': {'algorithm': algorithm.value}}

        return self._make_hapee_request(
            '/services/haproxy/configuration/backends',
            method=ProxyAPIMethod.POST,
            query_parameters=query_params,
            json_body=json_body,
        )

    def get_backend_servers(self, backend: str) -> PROXY_API_RESPONSE:
        return self._make_hapee_request(
            '/services/haproxy/configuration/servers', query_parameters={'backend': backend}
        )

    def add_server_to_backend(
        self, backend: str, server_name: str, server_address: str, port: int, resolver: Optional[str]
    ) -> PROXY_API_RESPONSE:
        query_params = {'backend': backend, 'force_reload': True}
        json_body = {'check': 'enabled', 'name': server_name, 'address': server_address, 'port': port}
        # check that server_address is in ip address format
        is_ip_address = None
        try:
            is_ip_address = ipaddress.ip_address(server_address) and True
        except ValueError:
            # the server_addr is not in ip address format
            is_ip_address = False
        json_body.update(
            {'resolvers': resolver, 'init-addr': 'last,libc,none'} if resolver and not is_ip_address else {}
        )

        return self._make_hapee_request(
            '/services/haproxy/configuration/servers',
            method=ProxyAPIMethod.POST,
            query_parameters=query_params,
            json_body=json_body,
        )

    def remove_server_from_backend(self, backend: str, server_name: str) -> PROXY_API_RESPONSE:
        query_params = {'backend': backend, 'force_reload': True}

        return self._make_hapee_request(
            f'/services/haproxy/configuration/servers/{server_name}',
            method=ProxyAPIMethod.DELETE,
            query_parameters=query_params,
        )

    def get_frontends(self) -> PROXY_API_RESPONSE:
        return self._make_hapee_request(endpoint='/services/haproxy/configuration/frontends')

    def add_frontend(
        self, name: str, port: int, backend: str, mode: CommunicationProtocol = CommunicationProtocol.TCP
    ) -> PROXY_API_RESPONSE:
        frontend_query_params = {'force_reload': True}
        frontend_json_body = {'name': name, 'mode': mode.value, 'default_backend': backend}

        frontend_response = self._make_hapee_request(
            '/services/haproxy/configuration/frontends',
            method=ProxyAPIMethod.POST,
            query_parameters=frontend_query_params,
            json_body=frontend_json_body,
        )
        frontend_name = frontend_response['name']

        bind_query_params = {'force_reload': True, 'frontend': frontend_name}
        bind_json_body = {'port': port, 'name': f'{frontend_name}_bind'}

        self._make_hapee_request(
            '/services/haproxy/configuration/binds',
            method=ProxyAPIMethod.POST,
            query_parameters=bind_query_params,
            json_body=bind_json_body,
        )

        return frontend_response

    def get_backend_server_runtime_settings(self, backend_name: str, server_name: str) -> PROXY_API_RESPONSE:
        query_params = {'backend': backend_name, 'name': server_name}

        return self._make_hapee_request(
            f'/services/haproxy/runtime/servers/{server_name}', query_parameters=query_params
        )

    def change_backend_server_state(
        self, backend_name: str, server_name: str, state: ProxyServerState
    ) -> PROXY_API_RESPONSE:
        query_params = {'backend': backend_name}
        json_body = {'admin_state': state.value}

        return self._make_hapee_request(
            f'/services/haproxy/runtime/servers/{server_name}',
            method=ProxyAPIMethod.PUT,
            query_parameters=query_params,
            json_body=json_body,
        )

    def get_backend_stats(self, backend_name: str) -> PROXY_API_RESPONSE:
        query_params = {'type': 'backend', 'name': backend_name}

        return self._make_hapee_request('/services/haproxy/stats/native', query_parameters=query_params)

    def get_backend_server_stats(self, backend_name: str, server_name: str) -> PROXY_API_RESPONSE:
        query_params = {'type': 'server', 'parent': backend_name, 'name': server_name.lower()}

        return self._make_hapee_request('/services/haproxy/stats/native', query_parameters=query_params)

    def get_proxy_processes(self) -> PROXY_API_RESPONSE:
        return self._make_proxy_request('/haproxy/processes')

    def kill_proxy_processes(self, pid_to_exclude: int = 0) -> PROXY_API_RESPONSE:
        query_params = {'exclude_pid': pid_to_exclude}

        return self._make_proxy_request(
            '/haproxy/processes', method=ProxyAPIMethod.DELETE, query_parameters=query_params
        )


def check_proxy_api(func):
    def wrapper(self, *args, **kwargs):
        if self.api is None:
            raise ProxyError(103)

        return func(self, *args, **kwargs)

    return wrapper


class Proxy:
    def __init__(
        self,
        wazuh_backend: str,
        proxy_api: ProxyAPI,
        logger: logging.Logger,
        wazuh_connection_port: int = 1514,
        resolver: str = None,
    ):
        self.logger = logger
        self.wazuh_backend = wazuh_backend
        self.wazuh_connection_port = wazuh_connection_port
        self.api = proxy_api
        self.resolver = resolver

    def initialize(self):
        self.api.initialize()
        try:
            self.api.get_runtime_info()['version']
        except (KeyError, IndexError):
            raise ProxyError(104)

    @check_proxy_api
    def get_current_pid(self) -> int:
        return self.api.get_runtime_info()['pid']

    @check_proxy_api
    def get_current_backends(self) -> dict:
        api_response = self.api.get_backends()
        self.logger.trace('Obtained proxy backends')
        return {backend['name']: backend for backend in api_response['data']}

    def exists_backend(self, backend_name: str) -> bool:
        return backend_name in self.get_current_backends()

    @check_proxy_api
    def get_current_frontends(self) -> dict:
        api_response = self.api.get_frontends()
        self.logger.trace('Obtained proxy frontends')
        return {frontend['name']: frontend for frontend in api_response['data'] if 'default_backend' in frontend}

    def exists_frontend(self, frontend_name: str) -> bool:
        return frontend_name in self.get_current_frontends()

    @check_proxy_api
    def add_new_backend(
        self,
        name: str,
        mode: CommunicationProtocol = CommunicationProtocol.TCP,
        algorithm: ProxyBalanceAlgorithm = ProxyBalanceAlgorithm.LEAST_CONNECTIONS,
    ):
        self.api.add_backend(name=name, mode=mode, algorithm=algorithm)
        self.logger.trace(f"Added new proxy backend: '{name}'")

    @check_proxy_api
    def add_new_frontend(
        self, name: str, port: int, backend: str, mode: CommunicationProtocol = CommunicationProtocol.TCP
    ):
        self.api.add_frontend(name=name, port=port, backend=backend, mode=mode)
        self.logger.trace(f"Added new proxy frontend: '{name}'")

    @check_proxy_api
    def get_current_backend_servers(self) -> dict:
        api_response = self.api.get_backend_servers(self.wazuh_backend)
        self.logger.trace('Obtained proxy servers')
        return {server['name']: server['address'] for server in api_response['data']}

    @check_proxy_api
    def add_wazuh_manager(self, manager_name: str, manager_address: str, resolver: Optional[str]) -> dict:
        api_response = self.api.add_server_to_backend(
            backend=self.wazuh_backend,
            server_name=manager_name,
            server_address=manager_address,
            port=self.wazuh_connection_port,
            resolver=resolver,
        )
        self.logger.trace(
            f"Added new server '{manager_name}' {manager_address}:{self.wazuh_connection_port} to backend"
            f" '{self.wazuh_backend}'"
        )
        return api_response

    @check_proxy_api
    def remove_wazuh_manager(self, manager_name: str) -> dict:
        api_response = self.api.remove_server_from_backend(backend=self.wazuh_backend, server_name=manager_name)

        self.logger.trace(f"Removed server {manager_name} from backend '{self.wazuh_backend}'")
        return api_response

    @check_proxy_api
    def restrain_server_new_connections(self, server_name: str) -> dict:
        api_response = self.api.change_backend_server_state(
            backend_name=self.wazuh_backend, server_name=server_name, state=ProxyServerState.DRAIN
        )
        self.logger.trace(f"Changed Wazuh server '{server_name}' to {ProxyServerState.DRAIN.value.upper()} state")
        return api_response

    @check_proxy_api
    def allow_server_new_connections(self, server_name: str) -> dict:
        api_response = self.api.change_backend_server_state(
            backend_name=self.wazuh_backend, server_name=server_name, state=ProxyServerState.READY
        )
        self.logger.trace(f"Changed Wazuh server '{server_name}' to {ProxyServerState.READY.value.upper()} state")
        return api_response

    @check_proxy_api
    def get_wazuh_server_stats(self, server_name: str) -> dict:
        server_stats = self.api.get_backend_server_stats(backend_name=self.wazuh_backend, server_name=server_name)[0][
            'stats'
        ][0]['stats']

        self.logger.trace(f"Obtained server '{server_name}' stats")
        return server_stats

    @check_proxy_api
    def is_server_drain(self, server_name: str) -> bool:
        server_stats = self.api.get_backend_server_runtime_settings(
            backend_name=self.wazuh_backend, server_name=server_name
        )
        return server_stats['admin_state'] == ProxyServerState.DRAIN.value

    @check_proxy_api
    def get_wazuh_backend_stats(self, only_actives: bool = True) -> dict:
        backend_servers = [server['name'] for server in self.api.get_backend_servers(self.wazuh_backend)['data']]
        stats = {}

        for server_name in backend_servers:
            server_stats = self.get_wazuh_server_stats(server_name=server_name)
            if only_actives and server_stats['status'] != 'UP':
                continue
            stats[server_name] = server_stats

        return stats

    @check_proxy_api
    def get_wazuh_backend_server_connections(self) -> dict:
        current_connections_key = 'scur'
        server_stats = self.get_wazuh_backend_stats()
        return {server_name: server_stats[server_name][current_connections_key] for server_name in server_stats}

    @check_proxy_api
    def is_proxy_process_single(self) -> bool:
        haproxy_processes = self.api.get_proxy_processes()
        return len(haproxy_processes['data']['processes']) == 1
