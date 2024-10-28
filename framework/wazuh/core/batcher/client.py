import asyncio
from dataclasses import asdict
from typing import Optional

from wazuh.core.batcher.mux_demux import MuxDemuxQueue, Item
from wazuh.core.indexer.base import remove_empty_values
from wazuh.core.indexer.models.events import StatefulEvent


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

    def send_event(self, event: StatefulEvent) -> int:
        """Send an event through the RouterQueue.

        Parameters
        ----------
        event : StatefulEvent
            Event to send.

        Returns
        -------
        int
            Unique identifier assigned to the event.
        """
        item = Item(
            id=id(event),
            content=asdict(event, dict_factory=remove_empty_values),
            index_name=event.get_index_name()
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
