from dataclasses import asdict
from opensearchpy import exceptions
from uuid6 import uuid7
from wazuh.core.exception import WazuhError, WazuhResourceNotFound

from .base import BaseIndex
from .models import Agent

NAME_KEY = 'name'
PASSWORD_KEY = 'password'
SOURCE_KEY = '_source'


class AgentsIndex(BaseIndex):
    """Set of methods to interact with `agents` index."""

    INDEX = 'agents'

    async def create(self, id: uuid7, key: str, name: str) -> Agent:
        """Create a new agent.

        Parameters
        ----------
        id : uuid7
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
        WazuhError (1708)
            When already exists an agent with the provided id.
        """
        doc = Agent(id=id, key=key, name=name)
        try:
            await self._client.index(
                index=self.INDEX,
                id=doc.id,
                body=asdict(doc),
                op_type='create',
                refresh='wait_for'
            )
        except exceptions.ConflictError:
            raise WazuhError(1708, extra_message=id)
        else:
            return doc

    async def get(self, uuid: uuid7) -> Agent:
        try:
            data = self._client.get(index=self.INDEX, id=self.uuid)
        except exceptions.NotFoundError:
            raise WazuhResourceNotFound(1701)
        finally:
            return Agent(uuid=uuid, **data[SOURCE_KEY])

    async def delete(self, uuid: uuid7):
        try:
            self._client.delete(id=uuid)
        except exceptions.NotFoundError:
            raise WazuhResourceNotFound(1701)
