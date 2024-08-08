from dataclasses import asdict

from opensearchpy import exceptions
from uuid6 import uuid7
from wazuh.core.exception import WazuhError, WazuhResourceNotFound

from .base import BaseIndex
from .constants import (
    BODY_KEY,
    DELETED_KEY,
    FAILURES_KEY,
    ID_KEY,
    INDEX_KEY,
    QUERY_KEY,
    SOURCE_KEY,
    TERMS_KEY,
)
from .models import Agent
from .utils import get_source_items


class AgentsIndex(BaseIndex):
    """Set of methods to interact with `agents` index."""

    INDEX = 'agents'
    SECONDARY_INDEXES = []

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
        doc = Agent(id=id, name=name, raw_key=key)
        try:
            await self._client.index(
                index=self.INDEX, id=doc.id, body=asdict(doc), op_type='create', refresh='wait_for'
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

    async def delete(self, ids: list[str]) -> list:
        """Delete multiple agents that match with the given parameters.

        Parameters
        ----------
        ids : list[uuid7]
            Agent ids to delete.

        Returns
        -------
        list
            Ids of the deleted agents.

        """
        indexes = ','.join([self.INDEX, *self.SECONDARY_INDEXES])
        body = {QUERY_KEY: {TERMS_KEY: {'_id': ids}}}
        parameters = {INDEX_KEY: indexes, BODY_KEY: body}

        deleted_ids = []

        response = await self._client.delete_by_query(**parameters, refresh='true')

        if len(ids) == response[DELETED_KEY]:
            deleted_ids = ids
        elif response[FAILURES_KEY]:
            ids_after_delete = {
                item[ID_KEY]
                for item in get_source_items(await self._client.search(**parameters, _source_includes=ID_KEY))
            }
            deleted_ids = list(set(ids) & ids_after_delete)

        return deleted_ids

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
        parameters = {INDEX_KEY: self.INDEX, BODY_KEY: query}
        return (await self._client.search(**parameters))
