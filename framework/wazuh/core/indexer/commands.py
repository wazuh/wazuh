from dataclasses import asdict
from typing import List, Optional, Union

from uuid6 import UUID

from .base import BaseIndex, IndexerKey, remove_empty_values
from wazuh.core.exception import WazuhResourceNotFound
from wazuh.core.indexer.models.commands import Command, Result, Status

ID_KEY = 'id'
AGENT_ID_KEY = 'agent.id'
STATUS_KEY = 'status'


class CommandsIndex(BaseIndex):
    """Set of methods to interact with the commands index."""

    INDEX = 'commands'

    async def get(self, uuid: UUID, status: Status) -> Optional[List[Command]]:
        """Get commands with the provided status from an specific agent.

        Parameters
        ----------
        uuid : UUID
            Agent universally unique identifier.
        status: Status
            Command execution status.

        Returns
        -------
        Optional[ListCommand]
            Commands list or None.
        """
        body = {
            IndexerKey.QUERY: {
                IndexerKey.BOOL: {
                    IndexerKey.MUST: [
                        {IndexerKey.MATCH: {AGENT_ID_KEY: uuid}},
                        {IndexerKey.MATCH: {STATUS_KEY: status}},
                    ]
                }
            }
        }

        response = await self._client.search(index=self.INDEX, body=body)
        hits = response[IndexerKey.HITS][IndexerKey.HITS]
        if len(hits) == 0:
            return None

        commands = []
        for data in hits:
            commands.append(Command.from_dict(data[IndexerKey._ID], data[IndexerKey._SOURCE]))

        return commands

    async def update(self, items: List[Union[Command, Result]]) -> None:
        """Update commands.
        
        Parameters
        ----------
        items : List[Union[Command, Result]]
            List of commands or results to update.

        Raises
        ------
        WazuhResourceNotFound(2202)
            If no document exists with the id provided.
        """
        actions = []
        for item in items:
            actions.append({IndexerKey.UPDATE: {IndexerKey._INDEX: self.INDEX, IndexerKey._ID: item.id}})
            item_dict = asdict(item, dict_factory=remove_empty_values)
            # The ID field shouldn't be part of the document value
            item_dict.pop(ID_KEY, None)
            actions.append({IndexerKey.DOC: item_dict})

        # TODO(25121): Create an internal library to build opensearch requests and parse responses
        response = await self._client.bulk(actions, self.INDEX)
        for item in response[IndexerKey.ITEMS]:
            if item[IndexerKey.UPDATE][STATUS_KEY] == 404:
                raise WazuhResourceNotFound(2202)
