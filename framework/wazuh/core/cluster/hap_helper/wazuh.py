import logging
import re
from collections import defaultdict
from enum import Enum
from typing import Callable, Optional

from wazuh.agent import get_agents, reconnect_agents
from wazuh.cluster import get_nodes_info
from wazuh.core.cluster.control import get_system_nodes
from wazuh.core.cluster.dapi.dapi import DistributedAPI


class WazuhAPIMethod(Enum):
    GET = 'get'
    POST = 'post'
    PUT = 'put'
    DELETE = 'delete'


class WazuhAgent:
    RECONNECTION_VERSION_MAJOR = 4
    RECONNECTION_VERSION_MINOR = 3
    AGENT_VERSION_REGEX = re.compile(r'.*v(\d+)\.(\d+)\.\d+')

    @classmethod
    def can_reconnect(cls, agent_version: str) -> bool:
        major, minor = cls.AGENT_VERSION_REGEX.match(agent_version).groups()
        return int(major) >= cls.RECONNECTION_VERSION_MAJOR and int(minor) >= cls.RECONNECTION_VERSION_MINOR

    @classmethod
    def get_agents_able_to_reconnect(cls, agents_list: list[dict]) -> list[str]:
        return [agent['id'] for agent in agents_list if cls.can_reconnect(agent['version'])]


class WazuhAPI:
    AGENTS_MAX_LIMIT = 100000
    API_RETRIES = 5
    TIMEOUT_ERROR_CODE = 3021

    def __init__(
        self,
        address: str,
        logger: logging.Logger,
        port: int = 55000,
        username: str = 'wazuh',
        password: str = 'wazuh',
        excluded_nodes: list | None = None,
    ):
        self.logger = logger
        self.address = address
        self.port = port
        self.username = username
        self.password = password
        self.excluded_nodes = excluded_nodes or []

        self.token = ''

    async def _make_dapi_call(self, f: Callable, f_kwargs: Optional[dict] = None, **kwargs) -> dict:
        ret_val = await DistributedAPI(f=f, f_kwargs=f_kwargs, logger=self.logger, **kwargs).distribute_function()
        if isinstance(ret_val, Exception):
            self.logger.error(f'Unexpected error calling {f.__name__}')
            raise ret_val
        return ret_val

    async def get_cluster_nodes(self) -> dict:
        data = await self._make_dapi_call(
            f=get_nodes_info,
            request_type='local_master',
            is_async=True,
            local_client_arg='lc',
            nodes=await get_system_nodes(),
        )

        return {item['name']: item['ip'] for item in data.affected_items if item['name'] not in self.excluded_nodes}

    async def reconnect_agents(self, agent_list: list = None) -> dict:
        data = await self._make_dapi_call(
            f=reconnect_agents,
            f_kwargs={'agent_list': agent_list},
            request_type='distributed_master',
        )

        return data.affected_items

    async def get_agents_node_distribution(self) -> dict:
        agent_distribution = defaultdict(list)

        f_kwargs = {
            'select': ['node_name', 'version'],
            'sort': {'fields': ['version', 'id'], 'order': 'desc'},
            'filters': {'status': 'active'},
            'q': 'id!=000',
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
        f_kwargs = {
            'select': ['version'],
            'sort': {'fields': ['version', 'id'], 'order': 'desc'},
            'filters': {'status': 'active', 'node_name': node_name},
            'q': 'id!=000',
            'limit': limit or self.AGENTS_MAX_LIMIT,
        }

        data = await self._make_dapi_call(
            f=get_agents,
            f_kwargs=f_kwargs,
            request_type='local_master',
        )

        return data.affected_items
