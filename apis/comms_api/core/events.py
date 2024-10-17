from typing import List

from comms_api.models.events import StatefulEvents, StatelessEvents
from wazuh.core.engine import get_engine_client
from wazuh.core.indexer import get_indexer_client
from wazuh.core.batcher.client import BatcherClient
from wazuh.core.batcher.mux_demux import MuxDemuxQueue
from wazuh.core.indexer.models.events import TaskResult


async def create_stateful_events(events: StatefulEvents, batcher_queue: MuxDemuxQueue) -> List[TaskResult]:
    """Post new events to the indexer.

    Parameters
    ----------
    events : Events
        List of events to be posted.

    batcher_queue : MuxDemuxQueue
        Queue used by the BatcherClient for processing.

    Returns
    -------
    List[TaskResult]
        List of results from the bulk tasks.
    """
    async with get_indexer_client() as indexer_client:
        batcher_client = BatcherClient(queue=batcher_queue)
        return await indexer_client.events.create(events.events, batcher_client)


async def send_stateless_events(events: StatelessEvents) -> None:
    """Send new events to the engine.

    Parameters
    ----------
    events : StatelessEvents
        Stateless events list.
    """
    async with get_engine_client() as engine_client:
        await engine_client.events.send(events.events)
