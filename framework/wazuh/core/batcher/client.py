import asyncio
from typing import Optional

from wazuh.core.batcher.mux_demux import MuxDemuxQueue, Item, Packet
from wazuh.core.indexer.models.events import AgentMetadata, Header, get_module_index_name


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
    def __init__(self, queue: MuxDemuxQueue, wait_frequency: float = 0.05):
        self.queue = queue
        self.wait_frequency = wait_frequency

    def send_event(self, packet: Packet):
        """Send an event through the RouterQueue.

        Parameters
        ----------
        agent_metadata : AgentMetadata
            Agent metadata.
        header : Header
            Event header.
        data : dict
            Event data.
        """
        self.queue.send_to_mux(packet)

    async def get_response(self, item_id: int) -> Packet:
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
            
            await asyncio.sleep(self.wait_frequency)
