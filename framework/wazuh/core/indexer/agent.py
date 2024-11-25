from typing import List, Optional

from opensearchpy import exceptions
# There's no other way to access these classes
from opensearchpy._async.helpers.update_by_query import AsyncUpdateByQuery
from opensearchpy._async.helpers.search import AsyncSearch

from wazuh.core.indexer.base import BaseIndex, IndexerKey
from wazuh.core.indexer.models.agent import Agent, Host
from wazuh.core.indexer.utils import get_source_items
from wazuh.core.exception import WazuhError, WazuhResourceNotFound

DEFAULT_GROUP = 'default'
AGENT_KEY = 'agent'


class AgentsIndex(BaseIndex):
    """Set of methods to interact with the `agents` index."""

    INDEX = '.agents'
    SECONDARY_INDEXES = []
    REMOVE_GROUP_SCRIPT = """
    for (int i=ctx._source.agent.groups.length-1; i>=0; i--) {
        if (ctx._source.agent.groups[i] == params.group) {
            ctx._source.agent.groups.remove(i);
        }
    }
    """

    async def create(
        self,
        id: str,
        name: str,
        key: str,
        type: str,
        version: str,
        groups: List[str] = None,
        host: Host = None,
    ) -> Agent:
        """Create a new agent.

        Parameters
        ----------
        id : str
            Agent ID.
        name : str
            Agent name.
        key : str
            Agent key.
        type : str
            Agent type.
        version : str
            Agent version.
        groups : str
            Agent groups.
        host : Host
            Agent host information.

        Raises
        ------
        WazuhError(1708)
            If an agent with the provided ID already exists.

        Returns
        -------
        Agent : dict
            The created agent instance.
        """
        group_list = [DEFAULT_GROUP]
        if groups is not None:
            group_list.extend(groups)

        agent = Agent(
            id=id,
            name=name,
            raw_key=key,
            type=type,
            version=version,
            groups=group_list,
            host=host if host else None
        )
        try:
            await self._client.index(
                index=self.INDEX,
                id=id,
                body={AGENT_KEY: agent.to_dict()},
                op_type='create',
                refresh='wait_for'
            )
        except exceptions.ConflictError:
            raise WazuhError(1708, extra_message=id)

        return agent

    async def delete(self, ids: List[str]) -> list:
        """Delete multiple agents that match with the given parameters.

        Parameters
        ----------
        ids : List[str]
            Agent ids to delete.

        Returns
        -------
        list
            Ids of the deleted agents.
        """
        indexes = ','.join([self.INDEX, *self.SECONDARY_INDEXES])
        body = {IndexerKey.QUERY: {IndexerKey.TERMS: {IndexerKey._ID: ids}}}
        parameters = {IndexerKey.INDEX: indexes, IndexerKey.BODY: body, IndexerKey.CONFLICTS: 'proceed'}

        await self._client.delete_by_query(**parameters, refresh='true')

        return ids

    async def search(
        self,
        query: dict,
        select: Optional[str] = None,
        exclude: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        sort: Optional[str] = None
    ) -> List[Agent]:
        """Perform a search operation with the given query.

        Parameters
        ----------
        query : dict
            DSL query.
        select : Optional[str], optional
            A comma-separated list of fields to include in the response, by default None.
        exclude : Optional[str], optional
            A comma-separated list of fields to exclude from the response, by default None.
        offset : Optional[int], optional
            The starting index to search from, by default None.
        limit : Optional[int], optional
            How many results to include in the response, by default None.
        sort : Optional[str], optional
            A comma-separated list of fields to sort by, by default None.

        Returns
        -------
        dict
            The search result.
        """
        parameters = {IndexerKey.INDEX: self.INDEX, IndexerKey.BODY: query}
        results = await self._client.search(
            **parameters, _source_includes=select, _source_excludes=exclude, size=limit, from_=offset, sort=sort
        )
        return [Agent(**item[AGENT_KEY]) for item in get_source_items(results)]

    async def get(self, uuid: str) -> Agent:
        """Retrieve an agent information.

        Parameters
        ----------
        uuid : str
            Agent unique identifier.

        Raises
        ------
        WazuhResourceNotFound(1701)
            If no agents exist with the uuid provided.

        Returns
        -------
        Agent
            Agent object.
        """
        try:
            data = await self._client.get(index=self.INDEX, id=uuid)
        except exceptions.NotFoundError:
            raise WazuhResourceNotFound(1701)

        return Agent(**data[IndexerKey._SOURCE][AGENT_KEY])

    async def update(self, uuid: str, agent: Agent) -> None:
        """Update an agent.

        Parameters
        ----------
        uuid : str
            Agent unique identifier.
        agent : Agent
            Agent fields. Only specified fields are updated.

        Raises
        ------
        WazuhResourceNotFound(1701)
            If no agents exist with the uuid provided.
        """
        try:
            body = {IndexerKey.DOC: {AGENT_KEY: agent.to_dict()}}
            await self._client.update(index=self.INDEX, id=uuid, body=body)
        except exceptions.NotFoundError:
            raise WazuhResourceNotFound(1701)

    # Group queries

    async def delete_group(self, group_name: str):
        """Delete a group that matches the given parameters.

        Parameters
        ----------
        group_name : str
            Group to delete.
        """
        query = AsyncUpdateByQuery(using=self._client, index=self.INDEX) \
            .filter({
                IndexerKey.TERM: {
                    'agent.groups': group_name
                }
            }) \
            .script(
                source=self.REMOVE_GROUP_SCRIPT,
                lang=IndexerKey.PAINLESS,
                params={'group': group_name}
            )
        _ = await query.execute()

    async def get_group_agents(self, group_name: str) -> List[Agent]:
        """Get the agents belonging to a specific group.

        Parameters
        ----------
        group_name : str
            Group name.

        Returns
        -------
        agents : List[Agent]
            Agents list.
        """
        query = AsyncSearch(using=self._client, index=self.INDEX).filter({
            IndexerKey.TERM: {
                'agent.groups': group_name
            }
        })
        response = await query.execute()

        agents = []
        for hit in response:
            agents.append(Agent(**hit.to_dict()[AGENT_KEY]))

        return agents

    async def add_agents_to_group(self, group_name: str, agent_ids: List[str], override: bool = False):
        """Add agents to a group.

        Parameters
        ----------
        group_name : str
            Group name.
        agent_ids : List[str]
            Agent IDs.
        override : bool
            Replace all groups with the specified one.
        """
        await self._update_groups(group_name=group_name, agent_ids=agent_ids, override=override)

    async def remove_agents_from_group(self, group_name: str, agent_ids: List[str]):
        """Remove agent from a group.

        Parameters
        ----------
        group_name : str
            Group name.
        agent_ids : List[str]
            Agent IDs.
        """
        await self._update_groups(group_name=group_name, agent_ids=agent_ids, remove=True)

    async def _update_groups(self, group_name: str, agent_ids: List[str], remove: bool = False, override: bool = False):
        """Add or remove group from multiple agents.

        Parameters
        ----------
        group_name : str
            Group name.
        agent_ids : List[str]
            Agent IDs.
        remove : bool
            Whether to remove agents from the group. By default it is added.
        override : bool
            Replace all groups with the specified one. Only works if `remove` is False.
        """
        if remove:
            source = self.REMOVE_GROUP_SCRIPT
        else:
            if override:
                source = 'ctx._source.agent.groups = new String[] {params.group};'
            else:
                source = """
                if (ctx._source.agent.groups == null) {
                    ctx._source.agent.groups = new String[] {params.group};
                } else {
                    ctx._source.agent.groups.add(params.group);
                }
                """

        query = AsyncUpdateByQuery(using=self._client, index=self.INDEX) \
            .filter(IndexerKey.IDS, values=agent_ids) \
            .script(
                source=source,
                lang=IndexerKey.PAINLESS,
                params={'group': group_name}
            )
        _ = await query.execute()
