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

    async def create(self, id: str, key: str, name: str) -> Agent:
        """Create a new agent.

        Parameters
        ----------
        id : str
            Identifier of the new agent.
        key : str
            Key of the new agent.
        name : str
            Name of the new agent.

        Returns
        -------
        Agent
            The created agent instance.

        Raises
        ------
        WazuhError(1708)
            When already exists an agent with the provided id.
        """
        agent = Agent(id=id, raw_key=key, name=name)
        try:
            await self._client.index(
                index=self.INDEX,
                id=agent.id,
                body=asdict(agent),
                op_type='create',
                refresh='wait_for'
            )
        except exceptions.ConflictError:
            raise WazuhError(1708, extra_message=id)
        else:
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

        return Agent(**data[IndexerKey._SOURCE])

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
        group_names : List[str]
            Groups to delete.
        """
        query = AsyncUpdateByQuery(using=self._client, index=self.INDEX) \
            .filter(IndexerKey.TERM, groups=group_name) \
            .script(
                source=self.REMOVE_GROUP_SCRIPT,
                lang='painless',
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
        List[Agent]
            Agents list.
        """
        query = AsyncSearch(using=self._client, index=self.INDEX).filter(IndexerKey.TERM, groups=group_name)
        response = await query.execute()

        agent_ids = []
        for hit in response:
            agent_ids.append(Agent(id=hit.meta.id, **hit.to_dict()))

        return agent_ids
    
    async def add_agents_to_group(self, agent_ids: List[str], group_name: str):
        """Add agents to a group.

        Parameters
        ----------
        agent_ids : List[str]
            Agent IDs.
        group_name : str
            Group name.
        """
        query = AsyncUpdateByQuery(using=self._client, index=self.INDEX) \
            .filter(IndexerKey.IDS, values=agent_ids) \
            .script(
                source='ctx._source.groups += ","+params.group',
                lang='painless',
                params={'group': group_name}
            )
        _ = await query.execute()
    
    async def remove_agents_from_group(self, agent_ids: List[str], group_name: str):
        """Remove agent from a group.

        Parameters
        ----------
        agent_ids : List[str]
            Agent IDs.
        group_name : str
            Group name.
        """
        if remove:
            source = self.REMOVE_GROUP_SCRIPT
        else:
            if override:
                source = 'ctx._source.groups = params.group'
            else:
                source = """
                if (ctx._source.groups == null) {
                    ctx._source.groups = params.group;
                } else {
                    ctx._source.groups += ","+params.group;
                }
                """

        query = AsyncUpdateByQuery(using=self._client, index=self.INDEX) \
            .filter(IndexerKey.IDS, values=agent_ids) \
            .script(
                source='ctx._source.groups = ctx._source.groups.replace(","+params.group, "").replace(params.group, "")',
                lang='painless',
                params={'group': group_name}
            )
        _ = await query.execute()

