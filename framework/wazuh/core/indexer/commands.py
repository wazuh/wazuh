from dataclasses import asdict
from typing import List, Optional

from opensearchpy import NotFoundError
from uuid6 import UUID

from .base import BaseIndex, IndexerKey, remove_empty_values
from wazuh.core.indexer.models.commands import Command, Status
from wazuh.core.exception import WazuhResourceNotFound

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

    async def update(self, commands: List[Command]) -> None:
        """Update commands.
        
        Parameters
        ----------
        commands : List[Command]
            List of commands to update.

        Raises
        ------
        WazuhResourceNotFound(2202)
            If no document exists with the id provided.
        """
        actions = []
        for command in commands:
            actions.append({IndexerKey.UPDATE: {IndexerKey._INDEX: self.INDEX, IndexerKey._ID: command.id}})
            command_dict = asdict(command, dict_factory=remove_empty_values)
            actions.append({IndexerKey.DOC: command_dict})

        try:
            await self._client.bulk(actions, self.INDEX)
        except NotFoundError:
            raise WazuhResourceNotFound(2202)
