from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.models.events import Events


async def post_stateful_events(events: Events) -> dict:
    """Post stateful events to the indexer.
    
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
       return await indexer_client.events.post(events)
