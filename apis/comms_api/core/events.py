from comms_api.models.events import StatefulEvents, StatelessEvents
from wazuh.core.engine import get_engine_client
from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.models.events import Events
from wazuh.core.batcher.client import BatcherClient
from wazuh.core.batcher.mux_demux import MuxDemuxQueue


async def create_stateful_events(events: Events, batcher_queue: MuxDemuxQueue) -> dict:
    """Post new events to the indexer.

    Parameters
    ----------
    events : Events
        List of events to be posted.

    batcher_queue : MuxDemuxQueue
        The queue used by the BatcherClient for processing.

    Returns
    -------
    dict
        Dictionary with the indexer response.
    """
    async with get_indexer_client() as indexer_client:
        batcher_client = BatcherClient(queue=batcher_queue)
        return await indexer_client.events.create(events, batcher_client)
