import asyncio
from dataclasses import asdict
from typing import List
from uuid import UUID

from .base import BaseIndex
from wazuh.core.indexer.models.events import StatefulEvent
from wazuh.core.indexer.bulk import MixinBulk
from wazuh.core.batcher.client import BatcherClient

from opensearchpy import AsyncOpenSearch


class EventsIndex(BaseIndex, MixinBulk):
    """Set of methods to interact with the stateful events indices."""

    def __init__(self, client: AsyncOpenSearch):
        super().__init__(client)

    async def create(self, events: List[StatefulEvent], batcher_client: BatcherClient) -> dict:
        """Post new events to the indexer.

        Parameters
        ----------
        events : List[StatefulEvent]
            List of events.
        batcher_client : BatcherClient
            Client responsible for sending the events to the batcher and managing responses.

        Returns
        -------
        dict
            Indexer response for each one of the events.
        """
        ids: List[UUID] = []
        response = {'events': []}

        # Sends the events to the batcher
        for event in events:
            uid_of_request = batcher_client.send_event(asdict(event))
            ids.append(uid_of_request)

        # Create tasks using a lambda function to obtain the result of each one
        tasks = []
        for uid in ids:
            task = asyncio.create_task(
                (lambda u: batcher_client.get_response(u))(uid)
            )
            tasks.append(task)

        # Wait for all of them and create response
        results = await asyncio.gather(*tasks)
        for result in results:
            response['events'].append({
                'id': result['_id'],
                'result': result['result'],
                'status': result['status']
            })

        return response
