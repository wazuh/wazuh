import uuid
import asyncio
from typing import Optional

from wazuh.core.batcher.mux_demux import MuxDemuxQueue


class BatcherClient:
    """
    A client for sending and receiving events via a MuxDemuxQueue.

    Parameters
    ----------
    queue : MuxDemuxQueue
        The MuxDemuxQueue instance used to route messages.
    """
    def __init__(self, queue: MuxDemuxQueue, frequency_of_wait: int = 0.1):
        self.queue = queue
        self.frequency_of_wait = frequency_of_wait

    def send_event(self, uid: str, event) -> uuid.UUID:
        """
        Sends an event through the RouterQueue with a newly assigned unique identifier.

        Parameters
        ----------
        uid : str
            The unique identifier for the message.
        event : any
            The event to be sent.

        Returns
        -------
        uuid.UUID
            The unique identifier assigned to the event.
        """
        return self.queue.send_to_mux(uid, event)

    # TODO - Investigate possibility of changing it to run_in_executor
    async def get_response(self, uid: str) -> Optional[dict]:
        """
        Asynchronously waits for a response to become available and retrieves it.

        Parameters
        ----------
        uid : str
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
                await asyncio.sleep(self.frequency_of_wait)
