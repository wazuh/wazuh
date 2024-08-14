from typing import Dict, List, Optional

from opensearchpy import helpers
from uuid6 import UUID

from .base import BaseIndex, Key
from wazuh.core.indexer.models.commands import Command, Status
from wazuh.core.exception import WazuhResourceNotFound

AGENT_ID_KEY = 'agent.id'
STATUS_KEY = 'status'


class CommandsIndex(BaseIndex):
    """Set of methods to interact with the commands index."""

    INDEX = 'commands'

    async def get(self, uuid: UUID, status: Status) -> Optional[Dict[str, Command]]:
        """Get commands with the provided status from an specific agent.

        Parameters
        ----------
        uuid : UUID
            Agent universally unique identifier.
        status: Status
            Command execution status.

        Returns
        -------
        Optional[Dict[str, Command]]
            Dictionary with document IDs and commands, or None.
        """
        body = {
            Key.QUERY: {
                Key.MATCH: {
                   AGENT_ID_KEY: uuid,
                   STATUS_KEY: status,
                } 
            }
        }
        # TODO: format response or return None
        return await self._client.search(index=self.INDEX, body=body)

    async def update(self, document_ids: List[str], status: Status) -> None:
        """Update commands status by their document ID.
        
        Parameters
        ----------
        document_ids : str
            Documents IDs.
        status : Status
            New command status.

        Raises
        ------
        WazuhResourceNotFound(2202)
            If no document exists with the id provided.
        """
        actions = []
        for document_id in document_ids:
            actions.append({
                Key.UPDATE: {
                    Key._INDEX: self.INDEX, 
                    Key._ID: document_id,
                    STATUS_KEY: status
                }
            })

        try:
            await helpers.async_bulk(self._client, actions=actions, stats_only=True)
        except helpers.BulkIndexError:
            raise WazuhResourceNotFound(2202)
