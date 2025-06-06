from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from wazuh.core.exception import WazuhError, WazuhInternalError
from wazuh.core import common

from httpx import AsyncClient, AsyncHTTPTransport, ConnectError, Timeout, TimeoutException, UnsupportedProtocol, \
    RequestError

APPLICATION_JSON = 'application/json'


class AgentIDGroups:
    """Pair of agent ID and its groups."""

    def __init__(self, id: str, groups: list[str] = None):
        self.id = id
        self.groups = groups


class AgentStatus:
    """Agent status."""

    def __init__(self, active: int, disconnected: int, never_connected: int, pending: int):
        self.active = active
        self.disconnected = disconnected
        self.never_connected = never_connected
        self.pending = pending


class AgentsSummary:
    """Agents summary."""

    def __init__(self, agents_by_status: AgentStatus, agents_by_os: Any, agents_by_groups: Any):
        self.status = agents_by_status
        self.os = agents_by_os
        self.groups = agents_by_groups


class WazuhDBHTTPClient:
    """Represents a client to the wdb HTTP unix socket."""

    API_URL = 'http://localhost/v1'

    def __init__(self, retries: int = 5, timeout: float = 10):
        """Class constructor.

        Parameters
        ----------
        retries : int
            Number of connection retries.
        timeout : float
            Maximum number of seconds to wait
        """
        self.socket_path = f'{common.WDB_HTTP_SOCKET}.sock'

        try:
            transport = AsyncHTTPTransport(uds=self.socket_path, retries=retries)
            self._client = AsyncClient(transport=transport, timeout=Timeout(timeout))

        except (OSError, TimeoutException) as e:
            raise WazuhInternalError(2011, e)

    async def close(self) -> None:
        """Close the wazuh-db HTTP client."""
        await self._client.aclose()

    async def _get(self, endpoint: str) -> Any:
        """Send a GET request to the specified endpoint.
        
        Parameters
        ----------
        endpoint : str
            Endpoint name.
        
        Returns
        -------
        Any
            JSON response.
        """
        try:
            response = await self._client.get(url=f'{self.API_URL}{endpoint}', headers={'Accept': APPLICATION_JSON})
            if response.is_error:
                raise WazuhError(2012, extra_message=response.text)

        except RequestError as exc:
            raise WazuhError(2013, extra_message=str(exc))

        return response.json()
    
    async def _post(self, endpoint: str, data: Any, empty_response: bool = False) -> Any:
        """Send a POST request to the specified endpoint.

        Parameters
        ----------
        endpoint : str
            Endpoint name.
        data : Any
            JSON body.
        empty_response : bool
            Whether the endpoint returns an empty response or not. False by default.

        Returns
        -------
        Any
            JSON response.
        """
        try:
            response = await self._client.post(
                url=f'{self.API_URL}{endpoint}',
                json=data,
                headers={
                    'Accept': APPLICATION_JSON,
                    'Content-Type': APPLICATION_JSON,
                },
            )

            if response.is_error:
                raise WazuhError(2012, extra_message=response.text)

        except RequestError as exc:
            raise WazuhError(2013, extra_message=str(exc))
        
        if empty_response:
            return

        return response.json()

    async def get_agents_ids(self) -> list[str]:
        """Get system agents IDs.
        
        Returns
        -------
        list[str]
            Agent IDs.
        """
        return await self._get('/agents/ids')
    
    async def get_agent_groups(self, agent_id: str) -> list[str]:
        """Get agent groups.
        
        Parameters
        ----------
        agent_id : str
            Agent ID.
        
        Returns
        -------
        list[str]
            Group names.
        """
        return await self._get(f'/agents/{agent_id}/groups')
    
    async def get_agents_groups(self) -> list[AgentIDGroups]:
        """Get system agents groups.
        
        Returns
        -------
        list[str]
            Group names.
        """
        response = await self._get('/agents/ids/groups')
        if not response:
            return []
        return [AgentIDGroups(id=key.zfill(3), groups=value) for key, value in response['data'].items()]

    async def get_group_agents(self, group_name: str) -> list[int]:
        """Get group agents.
        
        Parameters
        ----------
        group_name : str
            Group name.
        
        Returns
        -------
        list[int]
            Agent IDs.
        """
        return await self._get(f'/agents/ids/groups/{group_name}')
    
    async def get_agents_summary(self, agent_ids: list[str] = []) -> AgentsSummary:
        """Get agents information summary.
        
        Parameters
        ----------
        agent_ids : list[str]
            Agent ID list. By default, the summary of all agents is returned.
        
        Returns
        -------
        AgentsSummary
            Agents information summary.
        """
        ids = [int(agent_id) for agent_id in agent_ids]
        data = await self._post('/agents/summary', ids)
        return AgentsSummary(**data)
    
    async def get_agents_sync(self) -> dict:
        """Get agents synchronization information.
        
        Returns
        -------
        dict
            Agenst synchronization information.
        """
        return await self._get('/agents/sync')

    async def set_agents_sync(self, agents_sync: dict) -> None:
        """Set agents synchronization information.

        Parameters
        ----------
        agents_sync : dict
            Agenst synchronization information.
        """
        await self._post('/agents/sync', agents_sync, empty_response=True)


@asynccontextmanager
async def get_wdb_http_client() -> AsyncIterator[WazuhDBHTTPClient]:
    """Create and return the engine client.

    Returns
    -------
    AsyncIterator[WazuhDBHTTP]
        Wazuh DB HTTP client iterator.
    """
    client = WazuhDBHTTPClient()

    try:
        yield client
    except TimeoutException:
        raise WazuhInternalError(2014)
    except UnsupportedProtocol:
        raise WazuhInternalError(2015)
    except ConnectError:
        raise WazuhInternalError(2016)
    finally:
        await client.close()
