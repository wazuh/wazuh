import ipaddress
import json
import logging
from enum import Enum
from os.path import join
from typing import Literal, Optional, TypeAlias

import httpx
from wazuh.core.cluster.utils import ClusterFilter, context_tag
from wazuh.core.exception import WazuhHAPHelperError

JSON_TYPE: TypeAlias = dict | list[dict]
PROXY_API_RESPONSE: TypeAlias = JSON_TYPE | None
HTTP_PROTOCOL = Literal['http', 'https']
DEFAULT_TIMEOUT = 10.0


def _convert_to_seconds(milliseconds: int) -> int:
    """Convert the given milliseconds to seconds.

    Parameters
    ----------
    millisenconds : int
        Milliseconds to convert.

    Returns
    -------
    float
        The amount of seconds.
    """
    return int(milliseconds / 1000)


def _convert_to_milliseconds(seconds: int) -> int:
    """Convert the given seconds to milliseconds.

    Parameters
    ----------
    seconds : int
        Seconds to convert.

    Returns
    -------
    int
        The amount of milliseconds.
    """
    return int(seconds * 1000)


class ProxyAPIMethod(Enum):
    GET = 'get'
    POST = 'post'
    PUT = 'put'
    DELETE = 'delete'


class ProxyServerState(Enum):
    READY = 'ready'
    MAINTENANCE = 'maint'
    DRAIN = 'drain'
    DOWN = 'down'
    UP = 'up'


class CommunicationProtocol(Enum):
    TCP = 'tcp'
    HTTP = 'http'


class ProxyBalanceAlgorithm(Enum):
    ROUND_ROBIN = 'roundrobin'
    LEAST_CONNECTIONS = 'leastconn'


class ProxyAPI:
    """Wrapper for calling HAProxy REST API"""

    HAP_ENDPOINT = 'v2'

    def __init__(
        self,
        username: str,
        password: str,
        tag: str,
        address: str = 'localhost',
        port: int = 5555,
        protocol: HTTP_PROTOCOL = 'http',
        haproxy_cert_file: str | bool = True,
        client_cert_file: str | None = None,
        client_key_file: str | None = None,
        client_password: str | None = None
    ):
        self.username = username
        self.password = password
        self.address = address
        self.port = port
        self.tag = tag
        self.protocol = protocol
        # Required for HTTPS use
        self.haproxy_cert = haproxy_cert_file
        self.client_cert = (client_cert_file, client_key_file, client_password) \
            if client_cert_file and self.protocol == 'https' else None

        self.version = 0

    async def initialize(self):
        """Initialize the REST API client.

        Raises
        ------
        WazuhHAPHelperError
            In case of errors communicating with the HAProxy REST API.
        """
        try:
            async with httpx.AsyncClient(verify=self.haproxy_cert, cert=self.client_cert,
                                         timeout=httpx.Timeout(DEFAULT_TIMEOUT)) as client:
                response = await client.get(
                    join(f'{self.protocol}://', f'{self.address}:{self.port}', self.HAP_ENDPOINT, 'health'),
                    auth=(self.username, self.password),
                )
                if response.status_code == 401:
                    raise WazuhHAPHelperError(3046)
                elif response.status_code == 404:
                    raise WazuhHAPHelperError(3047)
        except httpx.ConnectError:
            raise WazuhHAPHelperError(
                3043, extra_message='Check connectivity and the configuration in the `ossec.conf`'
            )
        except httpx.RequestError as req_exc:
            raise WazuhHAPHelperError(3043, extra_message=str(req_exc))

    async def _make_hap_request(
        self,
        endpoint: str,
        method: ProxyAPIMethod = ProxyAPIMethod.GET,
        query_parameters: dict | None = None,
        json_body: dict | None = None,
    ) -> PROXY_API_RESPONSE:
        """Wrapper to make REST API calls.

        Parameters
        ----------
        endpoint : str
            Endpoint to call.
        method : ProxyAPIMethod, optional
            Method to use, by default ProxyAPIMethod.GET.
        query_parameters : dict | None, optional
            Query parameters to send in the request, by default None.
        json_body : dict | None, optional
            Data to send within the request, by default None.

        Returns
        -------
        PROXY_API_RESPONSE
            REST API response in JSON format.

        Raises
        ------
        WazuhHAPHelperError
            In case of errors communicating with the HAProxy REST API.
        """
        context_tag.set(self.tag)
        version_key = '_version'
        uri = join(f'{self.protocol}://', f'{self.address}:{self.port}', self.HAP_ENDPOINT, endpoint)
        query_parameters = query_parameters or {}
        query_parameters.update({'version': self.version})

        try:
            async with httpx.AsyncClient(verify=self.haproxy_cert,
                                         cert=self.client_cert, follow_redirects=True,
                                         timeout=httpx.Timeout(DEFAULT_TIMEOUT)) as client:
                response = await client.request(
                    method=method.value,
                    url=uri,
                    auth=(self.username, self.password),
                    json=json_body,
                    params=query_parameters,
                )
        except httpx.RequestError as request_exc:
            raise WazuhHAPHelperError(3044, extra_message=str(request_exc))

        if response.is_success:
            try:
                response = response.json()
            except json.JSONDecodeError:
                response = None

            if isinstance(response, dict) and version_key in response:
                self.version = response[version_key]
            elif method != ProxyAPIMethod.GET and 'configuration' in endpoint:
                await self.update_configuration_version()

            return response
        elif response.status_code == 401:
            raise WazuhHAPHelperError(3046)
        else:
            raise WazuhHAPHelperError(3045, extra_message=response.json()['message'])

    async def update_configuration_version(self):
        """Get the last version of the configuration schema and set it."""
        configuration_version = await self._make_hap_request('services/haproxy/configuration/version')
        self.version = configuration_version

    async def get_runtime_info(self) -> PROXY_API_RESPONSE:
        """Get the runtime information of the HAProxy instance.

        Returns
        -------
        PROXY_API_RESPONSE
            The runtime information.
        """
        return (await self._make_hap_request('services/haproxy/runtime/info'))[0]['info']

    async def get_global_configuration(self) -> dict:
        """Get the global configuration from HAProxy.

        Returns
        -------
        dict
            The current global configuration.
        """
        return (await self._make_hap_request('services/haproxy/configuration/global'))['data']

    async def update_global_configuration(self, new_configuration: dict):
        """Apply the new global configuration.

        Parameters
        ----------
        new_configuration : str
            New global configuration to apply.
        """
        await self._make_hap_request(
            'services/haproxy/configuration/global', json_body=new_configuration, method=ProxyAPIMethod.PUT
        )

    async def get_backends(self) -> PROXY_API_RESPONSE:
        """Get the configured backends.

        Returns
        -------
        PROXY_API_RESPONSE
            Information of configured backends.
        """
        return await self._make_hap_request(endpoint='services/haproxy/configuration/backends')

    async def add_backend(
        self,
        name: str,
        mode: CommunicationProtocol = CommunicationProtocol.TCP,
        algorithm: ProxyBalanceAlgorithm = ProxyBalanceAlgorithm.LEAST_CONNECTIONS,
    ) -> PROXY_API_RESPONSE:
        """Add a new backend to HAProxy instance.

        Parameters
        ----------
        name : str
            Name to set.
        mode : CommunicationProtocol, optional
            Protocol to use, by default CommunicationProtocol.TCP.
        algorithm : ProxyBalanceAlgorithm, optional
            Load balancing algorithm to use, by default ProxyBalanceAlgorithm.LEAST_CONNECTIONS.

        Returns
        -------
        PROXY_API_RESPONSE
            Information about the newly added backend.
        """
        query_params = {'force_reload': True}
        json_body = {'name': name, 'mode': mode.value, 'balance': {'algorithm': algorithm.value}}

        return await self._make_hap_request(
            'services/haproxy/configuration/backends',
            method=ProxyAPIMethod.POST,
            query_parameters=query_params,
            json_body=json_body,
        )

    async def get_backend_servers(self, backend: str) -> PROXY_API_RESPONSE:
        """Get the servers for the provided backend.

        Parameters
        ----------
        backend : str
            Backend name to query.

        Returns
        -------
        PROXY_API_RESPONSE
            The servers for the provided backend.
        """
        return await self._make_hap_request(
            'services/haproxy/configuration/servers', query_parameters={'backend': backend}
        )

    async def add_server_to_backend(
        self, backend: str, server_name: str, server_address: str, port: int, resolver: Optional[str] = None
    ) -> PROXY_API_RESPONSE:
        """Add a new server to the provided backend.

        Parameters
        ----------
        backend : str
            Backend to add the new server.
        server_name : str
            Name of the new server.
        server_address : str
            IP or DNS for the new server.
        port : int
            Port number to use with the new server.
        resolver : Optional[str]
            The name of the connection resolver to use.

        Returns
        -------
        PROXY_API_RESPONSE
            Information about the newly added server.
        """
        query_params = {'backend': backend, 'force_reload': True}
        json_body = {'check': 'enabled', 'name': server_name, 'address': server_address, 'port': port}

        is_ip_address = None
        try:
            is_ip_address = ipaddress.ip_address(server_address) and True
        except ValueError:
            is_ip_address = False

        json_body.update(
            {'resolvers': resolver, 'init-addr': 'last,libc,none'} if resolver and not is_ip_address else {}
        )

        return await self._make_hap_request(
            'services/haproxy/configuration/servers',
            method=ProxyAPIMethod.POST,
            query_parameters=query_params,
            json_body=json_body,
        )

    async def remove_server_from_backend(self, backend: str, server_name: str) -> PROXY_API_RESPONSE:
        """Remove a server from the backend.

        Parameters
        ----------
        backend : str
            The backend to remove the server.
        server_name : str
            The server to remove.

        Returns
        -------
        PROXY_API_RESPONSE
            Information about the removed server.
        """
        query_params = {'backend': backend, 'force_reload': True}

        return await self._make_hap_request(
            f'services/haproxy/configuration/servers/{server_name}',
            method=ProxyAPIMethod.DELETE,
            query_parameters=query_params,
        )

    async def get_frontends(self) -> PROXY_API_RESPONSE:
        """Returns the frontends configured in the HAProxy instance.

        Returns
        -------
        PROXY_API_RESPONSE
            Information of configured frontends.
        """
        return await self._make_hap_request(endpoint='services/haproxy/configuration/frontends')

    async def add_frontend(
        self, name: str, port: int, backend: str, mode: CommunicationProtocol = CommunicationProtocol.TCP
    ) -> PROXY_API_RESPONSE:
        """Add a new frontend to the HAProxy instance.

        Parameters
        ----------
        name : str
            Name of the new frontend.
        port : int
            Port number to use with the new frontend.
        backend : str
            Default backend to connect.
        mode : CommunicationProtocol, optional
            Communication protocol to use, by default CommunicationProtocol.TCP.

        Returns
        -------
        PROXY_API_RESPONSE
            Information about the newly created frontend.
        """
        frontend_query_params = {'force_reload': True}
        frontend_json_body = {'name': name, 'mode': mode.value, 'default_backend': backend}

        frontend_response = await self._make_hap_request(
            'services/haproxy/configuration/frontends',
            method=ProxyAPIMethod.POST,
            query_parameters=frontend_query_params,
            json_body=frontend_json_body,
        )
        frontend_name = frontend_response['name']

        bind_query_params = {'force_reload': True, 'frontend': frontend_name}
        bind_json_body = {'port': port, 'name': f'{frontend_name}_bind'}

        await self._make_hap_request(
            'services/haproxy/configuration/binds',
            method=ProxyAPIMethod.POST,
            query_parameters=bind_query_params,
            json_body=bind_json_body,
        )

        return frontend_response

    async def get_backend_server_runtime_settings(self, backend_name: str, server_name: str) -> PROXY_API_RESPONSE:
        """Get the settings of a backend server.

        Parameters
        ----------
        backend_name : str
            Backend name to query.
        server_name : str
            Server name to query.

        Returns
        -------
        PROXY_API_RESPONSE
            Settings information for the server.
        """
        query_params = {'backend': backend_name, 'name': server_name}

        return await self._make_hap_request(
            f'services/haproxy/runtime/servers/{server_name}', query_parameters=query_params
        )

    async def change_backend_server_state(
        self, backend_name: str, server_name: str, state: ProxyServerState
    ) -> PROXY_API_RESPONSE:
        """Set the status of a backend server.

        Parameters
        ----------
        backend_name : str
            Backend name to query.
        server_name : str
            Server name to query.
        state : ProxyServerState
            New state to set it.

        Returns
        -------
        PROXY_API_RESPONSE
            Information about the new server state.
        """
        query_params = {'backend': backend_name}
        json_body = {'admin_state': state.value}

        return await self._make_hap_request(
            f'services/haproxy/runtime/servers/{server_name}',
            method=ProxyAPIMethod.PUT,
            query_parameters=query_params,
            json_body=json_body,
        )

    async def get_backend_stats(self, backend_name: str) -> PROXY_API_RESPONSE:
        """Get the statistics of the provided backend.

        Parameters
        ----------
        backend_name : str
            Backend name to query.

        Returns
        -------
        PROXY_API_RESPONSE
            Statistics of the backend.
        """
        query_params = {'type': 'backend', 'name': backend_name}

        return await self._make_hap_request('services/haproxy/stats/native', query_parameters=query_params)

    async def get_backend_server_stats(self, backend_name: str, server_name: str) -> PROXY_API_RESPONSE:
        """Get the statistics of the provided backend server.

        Parameters
        ----------
        backend_name : str
            Backend to query.
        server_name : str
            Server to query.

        Returns
        -------
        PROXY_API_RESPONSE
            Statistics of the server.
        """
        query_params = {'type': 'server', 'parent': backend_name, 'name': server_name.lower()}

        return await self._make_hap_request('services/haproxy/stats/native', query_parameters=query_params)

    async def get_binds(self, frontend: str) -> PROXY_API_RESPONSE:
        """Returns the binds configured for the given frontend.

        Parameters
        ----------
        frontend : str
            Frontend to query.

        Returns
        -------
        PROXY_API_RESPONSE
            Information of configured frontends.
        """
        query_parameters = {'frontend': frontend}
        return await self._make_hap_request(
            endpoint='services/haproxy/configuration/binds', query_parameters=query_parameters
        )


class Proxy:
    def __init__(
        self,
        wazuh_backend: str,
        proxy_api: ProxyAPI,
        tag: str,
        wazuh_connection_port: int = 1514,
        resolver: str = None,
    ):
        self.tag = tag
        self.logger = self._get_logger(self.tag)
        self.wazuh_backend = wazuh_backend
        self.wazuh_connection_port = wazuh_connection_port
        self.api = proxy_api
        self.resolver = resolver
        self.hard_stop_after = None

    @staticmethod
    def _get_logger(tag: str) -> logging.Logger:
        """Get the configured logger.

        Parameters
        ----------
        tag : str
            Tag to use in log filter.

        Returns
        -------
        logging.Logger
            The configured logger.
        """
        logger = logging.getLogger('wazuh').getChild('Proxy')
        logger.addFilter(ClusterFilter(tag=tag, subtag='Proxy'))

        return logger

    async def initialize(self):
        """Initialize the ProxyAPI.

        Raises
        ------
        WazuhHAPHelperError
            In case of errors initializing ProxyAPI.
        """
        await self.api.initialize()
        try:
            (await self.api.get_runtime_info())['version']
            hard_stop_after = await self.get_hard_stop_after_value()
            self.hard_stop_after = _convert_to_seconds(hard_stop_after) if hard_stop_after is not None else None
        except (KeyError, IndexError):
            raise WazuhHAPHelperError(3048)

    async def get_hard_stop_after_value(self) -> Optional[str]:
        """Get the `hard-stop-after` value from the global configuration.

        Returns
        -------
        Optional[str]
            The value of the configuration.
        """
        return (await self.api.get_global_configuration()).get('hard_stop_after', None)

    async def set_hard_stop_after_value(
        self,
        active_agents: int,
        chunk_size: int,
        agent_reconnection_time: int,
        n_managers: int,
        server_admin_state_delay: int,
    ):
        """Calculate a dynamic value for `hard-stop-after` and set it.

        Parameters
        ----------
        active_agents : int
            Number of active agents.
        chunk_size : int
            Max number of agents to be reconnected at once.
        agent_reconnection_time : int
            Seconds to sleep after an agent chunk reconnection.
        n_manager : int
            Number of managers in the cluster.
        server_admin_state_delay : int
            Delay of server administration.
        """
        hard_stop_after = (active_agents / (n_managers * chunk_size)) * n_managers * agent_reconnection_time + (
            n_managers * server_admin_state_delay * 2
        )

        if self.hard_stop_after is None or self.hard_stop_after != hard_stop_after:
            configuration = await self.api.get_global_configuration()
            configuration['hard_stop_after'] = _convert_to_milliseconds(hard_stop_after)

            await self.api.update_global_configuration(new_configuration=configuration)
            self.hard_stop_after = hard_stop_after
            self.logger.info(f'Set `hard-stop-after` with {hard_stop_after} seconds.')

    async def get_current_pid(self) -> int:
        """Get the current HAProxy PID.

        Returns
        -------
        int
            Current PID.
        """
        return (await self.api.get_runtime_info())['pid']

    async def get_current_backends(self) -> dict:
        """Get the current backends from the Proxy.

        Returns
        -------
        dict
            The backends.
        """
        api_response = await self.api.get_backends()
        self.logger.debug2('Obtained proxy backends')
        return {backend['name']: backend for backend in api_response['data']}

    async def exists_backend(self, backend_name: str) -> bool:
        """Check if the provided backend exists.

        Parameters
        ----------
        backend_name : str
            Backend to check.

        Returns
        -------
        bool
            True if exists else False.
        """
        return backend_name in await self.get_current_backends()

    async def get_current_frontends(self) -> dict:
        """Get the current frontends from the Proxy.

        Returns
        -------
        dict
            The frontends.
        """
        api_response = await self.api.get_frontends()
        self.logger.debug2('Obtained proxy frontends')

        return {frontend['name']: frontend for frontend in api_response['data'] if 'default_backend' in frontend}

    async def exists_frontend(self, frontend_name: str) -> bool:
        """Check if the provided frontend exists.

        Parameters
        ----------
        frontend_name : str
            Frontend to check.

        Returns
        -------
        bool
            True if exists else False.
        """
        return frontend_name in await self.get_current_frontends()

    async def check_multiple_frontends(self, port: int, frontend_to_skip: str) -> bool:
        """Check if there are multiple frontends binding the given port.

        Parameters
        ----------
        port : int
            Port number to check.
        frontend_to_skip: str
            Skip the comprobation for the given frontend name.


        Returns
        -------
        bool
            True if exists mutiple frontends else False.
        """
        self.logger.debug(f'Checking multiple frontends for port {port}')
        frontends = await self.get_current_frontends()

        for frontend in frontends.keys():
            if frontend == frontend_to_skip:
                continue

            data = (await self.api.get_binds(frontend=frontend))['data']
            binds = [bind for bind in data if bind.get('port') == port]
            if binds:
                return True

        return False

    async def add_new_backend(
        self,
        name: str,
        mode: CommunicationProtocol = CommunicationProtocol.TCP,
        algorithm: ProxyBalanceAlgorithm = ProxyBalanceAlgorithm.LEAST_CONNECTIONS,
    ):
        """Add a new backend to the Proxy.

        Parameters
        ----------
        name : str
            Name for the new backend.
        mode : CommunicationProtocol, optional
            Communication protocol to use, by default CommunicationProtocol.TCP.
        algorithm : ProxyBalanceAlgorithm, optional
            Load balancing algorithm to use, by default ProxyBalanceAlgorithm.LEAST_CONNECTIONS.
        """
        await self.api.add_backend(name=name, mode=mode, algorithm=algorithm)
        self.logger.debug2(f"Added new proxy backend: '{name}'")

    async def add_new_frontend(
        self, name: str, port: int, backend: str, mode: CommunicationProtocol = CommunicationProtocol.TCP
    ):
        """Add a new frontend to the Proxy.

        Parameters
        ----------
        name : str
            Name for the new frontend.
        port : int
            Port number to use with the new frontend.
        backend : str
            Default backend to connect.
        mode : CommunicationProtocol, optional
            Communication protocol to use, by default CommunicationProtocol.TCP.
        """
        await self.api.add_frontend(name=name, port=port, backend=backend, mode=mode)
        self.logger.debug2(f"Added new proxy frontend: '{name}'")

    async def get_current_backend_servers(self) -> dict:
        """Get the current backend servers from the Proxy.

        Returns
        -------
        dict
            The backend servers.
        """
        api_response = await self.api.get_backend_servers(self.wazuh_backend)
        self.logger.debug2('Obtained proxy servers')
        return {server['name']: server['address'] for server in api_response['data']}

    async def add_wazuh_manager(self, manager_name: str, manager_address: str, resolver: Optional[str] = None) -> dict:
        """Add a new Wazuh manager to the Proxy.

        Parameters
        ----------
        manager_name : str
            Name of the Wazuh manager.
        manager_address : str
            IP or DNS for the Wazuh manager.
        resolver : Optional[str]
            Name of the connection resolver to use, by default None.

        Returns
        -------
        dict
            Information about the newly added manager.
        """
        api_response = await self.api.add_server_to_backend(
            backend=self.wazuh_backend,
            server_name=manager_name,
            server_address=manager_address,
            port=self.wazuh_connection_port,
            resolver=resolver,
        )
        self.logger.debug2(
            f"Added new server '{manager_name}' {manager_address}:{self.wazuh_connection_port} to backend"
            f" '{self.wazuh_backend}'"
        )
        return api_response

    async def remove_wazuh_manager(self, manager_name: str) -> dict:
        """Delete the given Wazuh manager from the Proxy.

        Parameters
        ----------
        manager_name : str
            Manager to remove.

        Returns
        -------
        dict
            Information about the removed manager.
        """
        api_response = await self.api.remove_server_from_backend(backend=self.wazuh_backend, server_name=manager_name)

        self.logger.debug2(f"Removed server {manager_name} from backend '{self.wazuh_backend}'")
        return api_response

    async def restrain_server_new_connections(self, server_name: str) -> dict:
        """Change the status of the given server to DRAIN to restrain new connections.

        Parameters
        ----------
        server_name : str
            The server to restrain.

        Returns
        -------
        dict
            Information about the server's new state.
        """
        api_response = await self.api.change_backend_server_state(
            backend_name=self.wazuh_backend, server_name=server_name, state=ProxyServerState.DRAIN
        )
        self.logger.debug2(f"Changed Wazuh server '{server_name}' to {ProxyServerState.DRAIN.value.upper()} state")
        return api_response

    async def allow_server_new_connections(self, server_name: str) -> dict:
        """Change the status of the given server to READY to allow new connections.

        Parameters
        ----------
        server_name : str
            The server that allows connections.

        Returns
        -------
        dict
            Information about the server's new state.
        """
        api_response = await self.api.change_backend_server_state(
            backend_name=self.wazuh_backend, server_name=server_name, state=ProxyServerState.READY
        )
        self.logger.debug2(f"Changed Wazuh server '{server_name}' to {ProxyServerState.READY.value.upper()} state")
        return api_response

    async def get_wazuh_server_stats(self, server_name: str) -> dict:
        """Get the statistics of the given server.

        Parameters
        ----------
        server_name : str
            The server name to query.

        Returns
        -------
        dict
            The statistics of the server.
        """
        server_stats = (
            await self.api.get_backend_server_stats(backend_name=self.wazuh_backend, server_name=server_name)
        )[0]['stats'][0]['stats']

        self.logger.debug2(f"Obtained server '{server_name}' stats")
        return server_stats

    async def is_server_drain(self, server_name: str) -> bool:
        """Check if the server is in DRAIN state.

        Parameters
        ----------
        server_name : str
            The server to check.

        Returns
        -------
        bool
            True if the server is in a DRAIN state, else False.
        """
        server_stats = await self.api.get_backend_server_runtime_settings(
            backend_name=self.wazuh_backend, server_name=server_name
        )
        return server_stats['admin_state'] == ProxyServerState.DRAIN.value

    async def get_wazuh_backend_stats(self, only_actives: bool = True) -> dict:
        """Get the statistics of the Wazuh backend.

        Parameters
        ----------
        only_actives : bool, optional
            Only include running servers, by default True.

        Returns
        -------
        dict
            The statistics of the Wazuh backend.
        """
        backend_servers = [
            server['name'] for server in (await self.api.get_backend_servers(self.wazuh_backend))['data']
        ]
        stats = {}

        for server_name in backend_servers:
            server_stats = await self.get_wazuh_server_stats(server_name=server_name)
            if only_actives and server_stats['status'] != 'UP':
                continue
            stats[server_name] = server_stats

        return stats

    async def get_wazuh_backend_server_connections(self) -> dict:
        """Get the active connections of the Wazuh backend server.

        Returns
        -------
        dict
            Information about the current connections.
        """
        current_connections_key = 'scur'
        server_stats = await self.get_wazuh_backend_stats()
        return {server_name: server_stats[server_name][current_connections_key] for server_name in server_stats}
