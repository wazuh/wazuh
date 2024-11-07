import asyncio
from dataclasses import asdict
from typing import Optional

from wazuh.core.batcher.mux_demux import MuxDemuxQueue, Item
from wazuh.core.indexer.base import remove_empty_values
from wazuh.core.indexer.models.events import AgentMetadata, StatefulEvent, get_module_index_name


class BatcherClient:
    """Client class to send and receive events via a MuxDemuxQueue.

    Parameters
    ----------
    queue : MuxDemuxQueue
        MuxDemuxQueue instance used to route items.
    wait_frequency: float
        The frequency, in seconds, at which the client checks for responses in the queue.
        Defaults to 0.1 seconds.

    """
    def __init__(self, queue: MuxDemuxQueue, wait_frequency: float = 0.1):
        self.queue = queue
        self.wait_frequency = wait_frequency

    def send_event(self, agent_metadata: AgentMetadata, event: StatefulEvent) -> int:
        """Send an event through the RouterQueue.

        Parameters
        ----------
        agent_metadata : AgentMetadata
            Agent metadata.
        event : StatefulEvent
            Event to send.

        Returns
        -------
        int
            Unique identifier assigned to the event.
        """
        metadata = {
            'agent': {
                'id': agent_metadata.uuid,
                'groups': agent_metadata.groups,
                'type': agent_metadata.type,
                'version': agent_metadata.version,
                'host': {
                    'architecture': agent_metadata.arch,
                    'ip': agent_metadata.ip,
                    'os': {
                        'full': agent_metadata.os
                    }
                },
            }
        }

        content = metadata | asdict(event.data, dict_factory=remove_empty_values)
        item = Item(
            id=event.document_id,
            content=content,
            operation=event.operation,
            index_name=get_module_index_name(event.module)
        )
        self.queue.send_to_mux(item)
        return item.id

    async def get_response(self, item_id: int) -> Optional[dict]:
        """Asynchronously wait for a response to become available and retrieve it.

        Parameters
        ----------
        item_id : int
            Unique identifier for the response.

        Returns
        -------
        Optional[dict]
            Indexer response if available, None otherwise.
        """
        while True:
            if not self.queue.is_response_pending(item_id):
                return self.queue.receive_from_demux(item_id)
            else:
                await asyncio.sleep(self.wait_frequency)
