from dataclasses import asdict
from typing import List

from opensearchpy import exceptions

from wazuh.core.indexer.base import BaseIndex, IndexerKey, remove_empty_values
from wazuh.core.indexer.models.agent import Agent
from wazuh.core.exception import WazuhError, WazuhResourceNotFound


class AgentsIndex(BaseIndex):
    """Set of methods to interact with the `agents` index."""

    INDEX = 'agents'
    SECONDARY_INDEXES = []

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
