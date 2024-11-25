import asyncio
from typing import List

from .base import BaseIndex
from wazuh.core.indexer.models.events import AgentMetadata, Header, Operation, StatefulEvent, TaskResult
from wazuh.core.indexer.base import IndexerKey
from wazuh.core.indexer.bulk import MixinBulk
from wazuh.core.batcher.client import BatcherClient

from opensearchpy import AsyncOpenSearch

HTTP_STATUS_OK = 200
HTTP_STATUS_PARTIAL_CONTENT = 206


class EventsIndex(BaseIndex, MixinBulk):
    """Set of methods to interact with the stateful events indices."""

    def __init__(self, client: AsyncOpenSearch):
        super().__init__(client)

    async def send(
        self,
        agent_metadata: AgentMetadata,
        headers: List[Header],
        events: List[StatefulEvent],
        batcher_client: BatcherClient
    ) -> List[TaskResult]:
        """Post new events to the indexer.

        Parameters
        ----------
        agent_metadata : AgentMetadata
            Agent metadata.
        headers : List[Header]
            List of events headers.
        events : List[StatefulEvent]
            List of events.
        batcher_client : BatcherClient
            Client responsible for sending the events to the batcher and managing responses.

        Returns
        -------
        results : List[TaskResult]
            Indexer response for each one of the bulk tasks.
        """
        tasks = []

        # Sends the events to the batcher
        for i, header in enumerate(headers):
            batcher_client.send_operation(
                agent_metadata=agent_metadata,
                header=header,
                event=events[i] if header.operation != Operation.DELETE else None
            )

            task = asyncio.create_task(
                (lambda u: batcher_client.get_response(u))(header.id)
            )
            tasks.append(task)

        # Wait for all of them and create response
        tasks_results = await asyncio.gather(*tasks)

        results: List[TaskResult] = []
        for result in tasks_results:
            status = result[IndexerKey.STATUS]
            if status >= HTTP_STATUS_OK and status <= HTTP_STATUS_PARTIAL_CONTENT:
                task_result = TaskResult(
                    id=result[IndexerKey._ID],
                    result=result[IndexerKey.RESULT],
                    status=status
                )
            else:
                task_result = TaskResult(
                    id='',
                    result=result[IndexerKey.ERROR][IndexerKey.REASON],
                    status=status
                )

            results.append(task_result)

        return results
