from typing import List

from comms_api.models.events import StatefulEvents, StatelessEvents
from wazuh.core.engine import get_engine_client
from wazuh.core.exception import WazuhError
from wazuh.core.indexer import get_indexer_client
from wazuh.core.batcher.client import BatcherClient
from wazuh.core.batcher.mux_demux import MuxDemuxQueue
from wazuh.core.indexer.models.events import AgentMetadata, TaskResult


async def create_stateful_events(
    agent_metadata: AgentMetadata,
    events: StatefulEvents,
    batcher_queue: MuxDemuxQueue
) -> List[TaskResult]:
    """Post new events to the indexer.

    Parameters
    ----------
    agent_metadata : AgentMetadata
        Agent metadata. 
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
        return await indexer_client.events.create(agent_metadata, events.events, batcher_client)


async def send_stateless_events(events: StatelessEvents) -> None:
    """Send new events to the engine.

    Parameters
    ----------
    events : StatelessEvents
        Stateless events list.
    """
    async with get_engine_client() as engine_client:
        await engine_client.events.send(events.events)


def parse_agent_metadata(agent_id: str, user_agent: str, agent_groups: str) -> AgentMetadata:
    """Parse the agent metadata from the different HTTP headers values.
    
    Parameters
    ----------
    agent_id : str
        Agent ID.
    user_agent : str
        User-Agent HTTP header value.
    agent_groups : str
        Agent-Groups HTTP header value.

    Returns
    -------
    AgentMetadata
        Agent metadata.    
    """
    values = user_agent.split(' ', 2)
    if len(values) != 3:
        raise WazuhError(1764)
    
    name = values[0]
    type = values[1]
    version = values[2]
    groups = agent_groups.split(',') if agent_groups != '' else []

    return AgentMetadata(
        id=agent_id,
        groups=groups,
        name=name,
        type=type,
        version=version
    )
