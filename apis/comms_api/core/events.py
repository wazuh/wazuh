from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.models.events import Events


async def index_stateful_events(events: Events) -> dict:
    """Index stateful events.
    
    Parameters
    ----------
    events : Events
        List of events.
    
    Returns
    -------
    dict
        Dictionary with the indexer response.
    """
    async with get_indexer_client() as indexer_client:
       return await indexer_client.events.index(events)
