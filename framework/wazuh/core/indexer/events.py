from dataclasses import asdict

from .base import BaseIndex
from wazuh.core.indexer.models.events import Events


class EventsIndex(BaseIndex):
    """Set of methods to interact with the stateful events indices."""

    async def post(self, events: Events) -> dict:
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
            resp = await self._client.index(index=event.get_index_name(), body=asdict(event))
            response.update({f'{i}': resp})

        return response
