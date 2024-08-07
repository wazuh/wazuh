import uuid
import asyncio
from typing import Optional

from .queue import MuxDemuxQueue


class BatcherClient:
    """
    A client for sending and receiving events via a MuxDemuxQueue.

    Parameters
    ----------
    router : MuxDemuxQueue
        The MuxDemuxQueue instance used to route messages.
    """
    def __init__(self, router: MuxDemuxQueue, frequency_of_wait: int = 0.1):
        self.router = router
        self.frequency_of_wait = frequency_of_wait

    def send_event(self, event) -> uuid.UUID:
        """
        Sends an event through the RouterQueue with a newly assigned unique identifier.

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
        return self.router.send_to_mux(assigned_uid, event)

    async def get_response(self, uid: uuid.UUID) -> Optional[dict]:
        """
        Asynchronously waits for a response to become available and retrieves it.

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
            if not self.router.is_response_pending(uid):
                result = self.router.receive_from_demux(uid)
                return result
            else:
                await asyncio.sleep(self.frequency_of_wait)
