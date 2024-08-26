from comms_api.models.events import StatefulEvents, StatelessEvents
from wazuh.core.engine import get_engine_client
from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.models.events import Events
from wazuh.core.batcher.client import BatcherClient


async def create_stateful_events(events: Events, batcher_queue) -> dict:
    """Post new events to the indexer.
    
    Parameters
    ----------
    events : StatefulEvents
        Stateful events list.
    
    Returns
    -------
    dict
        Dictionary with the indexer response.
    """
    async with get_indexer_client() as indexer_client:
        batcher_client = BatcherClient(queue=batcher_queue)
        return await indexer_client.events.create(events, batcher_client)
