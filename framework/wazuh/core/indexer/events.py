import asyncio
from typing import List
from uuid import UUID

from .base import BaseIndex
from wazuh.core.indexer.models.events import StatefulEvent, Result
from wazuh.core.indexer.base import IndexerKey
from wazuh.core.indexer.bulk import MixinBulk
from wazuh.core.batcher.client import BatcherClient

from opensearchpy import AsyncOpenSearch


class EventsIndex(BaseIndex, MixinBulk):
    """Set of methods to interact with the stateful events indices."""

    def __init__(self, client: AsyncOpenSearch):
        super().__init__(client)

    async def create(self, events: List[StatefulEvent], batcher_client: BatcherClient) -> List[Result]:
        """Post new events to the indexer.

        Parameters
        ----------
        events : List[StatefulEvent]
            List of events.
        batcher_client : BatcherClient
            Client responsible for sending the events to the batcher and managing responses.

        Returns
        -------
        tasks_results : List[Result]
            Indexer response for each one of the indexing tasks.
        """
        item_ids: List[UUID] = []

        # Sends the events to the batcher
        for event in events:
            item_id = batcher_client.send_event(event)
            item_ids.append(item_id)

        # Create tasks using a lambda function to obtain the result of each one
        tasks = []
        for id in item_ids:
            task = asyncio.create_task(
                (lambda u: batcher_client.get_response(u))(id)
            )
            tasks.append(task)

        # Wait for all of them and create response
        tasks_results = await asyncio.gather(*tasks)

        results: List[Result] = []
        for result in tasks_results:
            results.append(Result(
                id=result[IndexerKey._ID],
                result=result[IndexerKey.RESULT],
                status=result[IndexerKey.STATUS]
            ))

        return results
