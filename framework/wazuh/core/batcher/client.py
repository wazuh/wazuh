import uuid
import asyncio
from typing import Optional

from wazuh.core.batcher.mux_demux import MuxDemuxQueue


class BatcherClient:
    """A client for sending and receiving events via a MuxDemuxQueue.

    Parameters
    ----------
    queue : MuxDemuxQueue
        The MuxDemuxQueue instance used to route messages.
    wait_frequency: float
        The frequency, in seconds, at which the client checks for responses in the queue.
        Defaults to 0.1 seconds.

    """
    def __init__(self, queue: MuxDemuxQueue, wait_frequency: float = 0.1):
        self.queue = queue
        self.wait_frequency = wait_frequency

    def send_event(self, event) -> uuid.UUID:
        """Sends an event through the RouterQueue.

        Parameters
        ----------
        event : any
            The event to be sent.

        Returns
        -------
        uuid.UUID
            The unique identifier assigned to the event.
        """
        assigned_uid = uuid.uuid4()
        return self.queue.send_to_mux(assigned_uid, event)

    async def get_response(self, uid: uuid.UUID) -> Optional[dict]:
        """Asynchronously waits for a response to become available and retrieves it.

        Parameters
        ----------
        uid : uuid.UUID
            The unique identifier for the response.

        Returns
        -------
        Optional[dict]
            The response dictionary if available, None otherwise.
        """
        while True:
            if not self.queue.is_response_pending(uid):
                result = self.queue.receive_from_demux(uid)
                return result
            else:
                await asyncio.sleep(self.wait_frequency)
