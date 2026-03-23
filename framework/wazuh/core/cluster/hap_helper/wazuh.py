import logging
import re
from collections import defaultdict
from typing import Callable, Optional

from wazuh.agent import get_agents, reconnect_agents
from wazuh.cluster import get_nodes_info
from wazuh.core.cluster.control import get_system_nodes
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.cluster.utils import ClusterFilter, context_tag


class WazuhAgent:
    """Tools to handle Wazuh agents connections."""

    RECONNECTION_VERSION_MAJOR = 4
    RECONNECTION_VERSION_MINOR = 3
    AGENT_VERSION_REGEX = re.compile(r'.*v(\d+)\.(\d+)\.\d+')

    @classmethod
    def can_reconnect(cls, agent_version: str) -> bool:
        """Check if the agent can be re-connected.

        Parameters
        ----------
        agent_version : str
            The version of the agent to check.

        Returns
        -------
        bool
            True if the agent can be re-connected else False.
        """
        major, minor = cls.AGENT_VERSION_REGEX.match(agent_version).groups()
        return int(major) >= cls.RECONNECTION_VERSION_MAJOR and int(minor) >= cls.RECONNECTION_VERSION_MINOR

    @classmethod
    def get_agents_able_to_reconnect(cls, agents_list: list[dict]) -> list[str]:
        """Obtain agents that can be re-connected.

        Parameters
        ----------
        agents_list : list[dict]
            List of agents to analyze.

        Returns
        -------
        list[str]
            Agents that can be re-connected.
        """
        return [agent['id'] for agent in agents_list if cls.can_reconnect(agent['version'])]


class WazuhDAPI:
    """Class to call Wazuh DAPI functions."""

    AGENTS_MAX_LIMIT = 100000
    API_RETRIES = 5
    TIMEOUT_ERROR_CODE = 3021

    def __init__(
        self,
        tag: str,
        excluded_nodes: list | None = None,
    ):
        self.tag = tag
        self.logger = self._get_logger(self.tag)
        self.excluded_nodes = excluded_nodes or []

        self.token = ''

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
        logger = logging.getLogger('wazuh').getChild('WazuhDAPI')
        logger.addFilter(ClusterFilter(tag=tag, subtag='D API'))

        return logger

    async def _make_dapi_call(self, f: Callable, f_kwargs: Optional[dict] = None, **kwargs) -> dict:
        """Wrapper to call DAPI functions.

        Parameters
        ----------
        f : Callable
            Function to be executed.
        f_kwargs : Optional[dict], optional
             Arguments to be passed to function `f`, by default None.

        Returns
        -------
        dict
            The API response.

        Raises
        ------
        WazuhException
            Raise the exception returned by function `f`.
        """
        context_tag.set(self.tag)
        ret_val = await DistributedAPI(f=f, f_kwargs=f_kwargs, logger=self.logger, **kwargs).distribute_function()
        if isinstance(ret_val, Exception):
            self.logger.error(f'Unexpected error calling {f.__name__}')
            raise ret_val
        return ret_val

    async def get_cluster_nodes(self) -> dict:
        """Get the nodes of the cluster.

        Returns
        -------
        dict
            Information about the cluster nodes.
        """
        data = await self._make_dapi_call(
            f=get_nodes_info,
            request_type='local_master',
            is_async=True,
            local_client_arg='lc',
            nodes=await get_system_nodes(),
        )

        return {item['name']: item['ip'] for item in data.affected_items if item['name'] not in self.excluded_nodes}

    async def reconnect_agents(self, agent_list: list = None) -> dict:
        """Make an API call to reconnect agents.

        Parameters
        ----------
        agent_list : list, optional
            The agents to be re-connected, by default None.

        Returns
        -------
        dict
            Information about the re-connected agents.
        """
        data = await self._make_dapi_call(
            f=reconnect_agents,
            f_kwargs={'agent_list': agent_list},
            request_type='distributed_master',
            wait_for_complete=True
        )

        return data.affected_items

    async def get_agents_node_distribution(self) -> dict:
        """Get the distribution of connected agents.

        Returns
        -------
        dict
            The current distribution of the agents.
        """
        agent_distribution = defaultdict(list)

        f_kwargs = {
            'select': ['node_name', 'version'],
            'sort': {'fields': ['version', 'id'], 'order': 'desc'},
            'filters': {'status': 'active'},
            'limit': self.AGENTS_MAX_LIMIT,
        }

        data = await self._make_dapi_call(
            f=get_agents,
            f_kwargs=f_kwargs,
            request_type='local_master',
        )

        for agent in data.affected_items:
            agent_distribution[agent['node_name']].append({'id': agent['id'], 'version': agent['version']})

        return agent_distribution

    async def get_agents_belonging_to_node(self, node_name: str, limit: int = None) -> list[dict]:
        """Get the agents that are connected to a specific node.

        Parameters
        ----------
        node_name : str
            The name of the node to check.
        limit : int, optional
            Max number of agents to retrieve, by default None.

        Returns
        -------
        list[dict]
            The connected agents.
        """
        f_kwargs = {
            'select': ['version'],
            'sort': {'fields': ['version', 'id'], 'order': 'desc'},
            'filters': {'status': 'active', 'node_name': node_name},
            'limit': limit or self.AGENTS_MAX_LIMIT,
        }

        data = await self._make_dapi_call(
            f=get_agents,
            f_kwargs=f_kwargs,
            request_type='local_master',
        )

        return data.affected_items
