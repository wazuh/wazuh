from dataclasses import asdict
from typing import List

from opensearchpy import exceptions
# There's no other way to access these classes
from opensearchpy._async.helpers.update_by_query import AsyncUpdateByQuery
from opensearchpy._async.helpers.search import AsyncSearch

from wazuh.core.indexer.base import BaseIndex, IndexerKey, remove_empty_values
from wazuh.core.indexer.models.agent import Agent
from wazuh.core.exception import WazuhError, WazuhResourceNotFound


class AgentsIndex(BaseIndex):
    """Set of methods to interact with the `agents` index."""

    INDEX = 'agents'
    SECONDARY_INDEXES = []
    REMOVE_GROUP_SCRIPT = """
    def groups = ctx._source.groups.splitOnToken(",");
    def groups_str = "";

    for (int i=0; i < groups.length; i++) {
      if (groups[i] != params.group) {
        if (i != 0) {
          groups_str += ",";
        }

        groups_str += groups[i];
      }
    }

    ctx._source.groups = groups_str;
    """

    async def create(self, id: str, key: str, name: str, groups: str = None) -> dict:
        """Create a new agent.

        Parameters
        ----------
        id : str
            New agent ID.
        name : str
            New agent name.
        key : str
            New agent key.
        groups : str
            New agent groups.

        Raises
        ------
        WazuhError(1708)
            When already exists an agent with the provided id.

        Returns
        -------
        agent_dict : dict
            The created agent instance in a dictionary.
        """
        agent = Agent(raw_key=key, name=name, groups='default' + f',{groups}' if groups else '')
        agent_dict = asdict(agent, dict_factory=remove_empty_values)
        try:
            await self._client.index(
                index=self.INDEX,
                id=id,
                body=agent_dict,
                op_type='create',
                refresh='wait_for'
            )
        except exceptions.ConflictError:
            raise WazuhError(1708, extra_message=id)
        
        return agent_dict

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

    async def search(self, query: dict) -> dict:
        """Perform a search operation with the given query.

        Parameters
        ----------
        query : dict
            DSL query.

        Returns
        -------
        dict
            The search result.
        """
        parameters = {IndexerKey.INDEX: self.INDEX, IndexerKey.BODY: query}
        return await self._client.search(**parameters)

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

        return Agent(id=uuid, **data[IndexerKey._SOURCE])

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
            # Convert to a dictionary removing empty values to avoid updating them
            agent_dict = asdict(agent, dict_factory=remove_empty_values)
            body = {IndexerKey.DOC: agent_dict}
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
            .filter(IndexerKey.TERM, groups=group_name) \
            .script(
                source=self.REMOVE_GROUP_SCRIPT,
                lang='painless',
                params={'group': group_name}
            )
        _ = await query.execute()
    
    async def get_group_agents(self, group_name: str) -> List[dict]:
        """Get the agents belonging to a specific group.
        
        Parameters
        ----------
        group_name : str
            Group name.

        Returns
        -------
        agents : List[dict]
            Agents list.
        """
        query = AsyncSearch(using=self._client, index=self.INDEX).filter(IndexerKey.TERM, groups=group_name)
        response = await query.execute()

        agents = []
        for hit in response:
            agent = Agent(id=hit.meta.id, **hit.to_dict())
            if agent.groups is not None:
                agent.groups = agent.groups.split(',')
            agents.append(asdict(agent, dict_factory=remove_empty_values))

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
            source = 'ctx._source.groups = ctx._source.groups.replace(","+params.group, "").replace(params.group, "")'
        else:
            if override:
                source = 'ctx._source.groups = params.group'
            else:
                source = 'ctx._source.groups += ","+params.group'

        query = AsyncUpdateByQuery(using=self._client, index=self.INDEX) \
            .filter(IndexerKey.IDS, values=agent_ids) \
            .script(
                source=source,
                lang='painless',
                params={'group': group_name}
            )
        _ = await query.execute()

