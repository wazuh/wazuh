import asyncio
from dataclasses import asdict
from typing import List
from uuid import UUID

from .base import BaseIndex
from wazuh.core.indexer.models.events import StatefulEvent
from wazuh.core.indexer.models.events import Events
from wazuh.core.indexer.bulk import MixinBulk

from opensearchpy import AsyncOpenSearch


HARDCODED_EVENTS_INDEX_NAME = "events"


class EventsIndex(BaseIndex, MixinBulk):
    """Set of methods to interact with the stateful events indices."""
    INDEX = HARDCODED_EVENTS_INDEX_NAME

    def __init__(self, client: AsyncOpenSearch):
        super().__init__(client)

    async def create(self, events: Events, batcher_client) -> dict:
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
        list_of_uid: List[UUID] = []
        response = {}

        # Sends the events to the batcher
        for event in events.events:
            uid_of_request = batcher_client.send_event(asdict(event))
            list_of_uid.append(uid_of_request)

        # Create tasks using a lambda function to obtain the result of each one
        tasks = []
        for uid in list_of_uid:
            task = asyncio.create_task(
                (lambda u: batcher_client.get_response(u))(uid)
            )
            tasks.append(task)

        # Wait for all of them and create response
        results = await asyncio.gather(*tasks)
        for i, result in enumerate(results):
            response.update({f'{i}': result})

        return response
