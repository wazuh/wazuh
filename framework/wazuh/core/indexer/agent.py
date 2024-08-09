from dataclasses import asdict
from opensearchpy import exceptions
from uuid6 import UUID

from .base import BaseIndex
from .models import Agent
from wazuh.core.exception import WazuhError, WazuhResourceNotFound

NAME_KEY = 'name'
PASSWORD_KEY = 'password'
SOURCE_KEY = '_source'


class AgentsIndex(BaseIndex):
    """Set of methods to interact with the `agents` index."""

    INDEX = 'agents'

    async def create(self, id: UUID, key: str, name: str) -> Agent:
        """Create a new agent.

        Parameters
        ----------
        id : UUID
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
        doc = Agent(id=id, raw_key=key, name=name)
        try:
            await self._client.index(
                index=self.INDEX,
                id=doc.id,
                body=asdict(doc),
                op_type='create',
            )
        except exceptions.ConflictError:
            raise WazuhError(1708, extra_message=id)
        else:
            return doc

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

        return Agent(**data[SOURCE_KEY])

    async def delete(self, uuid: str) -> None:
        """Remove an agent.

        Parameters
        ----------
        uuid : str
            Agent unique identifier.
        
        Raises
        ------
        WazuhResourceNotFound(1701)
            If no agents exist with the uuid provided.
        """
        try:
            await self._client.delete(id=uuid)
        except exceptions.NotFoundError:
            raise WazuhResourceNotFound(1701)

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
            agent_dict = asdict(agent, dict_factory=lambda x: {k: v for (k, v) in x if v is not None})
            body = {'doc': agent_dict}
            await self._client.update(index=self.INDEX, id=uuid, body=body)
        except exceptions.NotFoundError:
            raise WazuhResourceNotFound(1701)
