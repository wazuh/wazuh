import asyncio

from wazuh.core.batcher.mux_demux import MuxDemuxQueue, Packet


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
        packet: Packet
            Packet to send to the Batcher.
        """
        self.queue.send_to_mux(packet)

    async def get_response(self, packet_id: int) -> Packet:
        """Asynchronously wait for a response to become available and retrieve it.

        Parameters
        ----------
        packet_id : int
            Unique identifier for the response.

        Returns
        -------
        Optional[dict]
            Indexer response if available, None otherwise.
        """
        while True:
            if not self.queue.is_response_pending(packet_id):
                return self.queue.receive_from_demux(packet_id)

            await asyncio.sleep(self.wait_frequency)
