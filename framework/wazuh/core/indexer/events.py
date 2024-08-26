from dataclasses import asdict
from typing import List

from .base import BaseIndex
from wazuh.core.indexer.models.events import StatefulEvent


class EventsIndex(BaseIndex):
    """Set of methods to interact with the stateful events indices."""

    async def create(self, events: List[StatefulEvent]) -> dict:
        """Post new events to the indexer.

        Parameters
        ----------
        events : Events
            List of events.
        
        Returns
        -------
        dict
            Indexer response for each one of the events.
        """
        # TODO(#24713): Implement server to indexer events batching
        response = {}
        for i, event in enumerate(events.events):
            resp = await self._client.create(index=event.get_index_name(), body=asdict(event))
            response.update({f'{i}': resp})

        return response
