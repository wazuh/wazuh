import asyncio
from typing import List
from multiprocessing import Process

from wazuh.core.batcher.buffer import Buffer
from wazuh.core.batcher.timer import TimerManager
from wazuh.core.batcher.mux_demux import MuxDemuxQueue, Message


class BatcherConfig:
    """
    Configuration for the Batcher, specifying limits for batching.

    Parameters
    ----------
    max_elements : int
        Maximum number of messages in a batch.
    max_size : int
        Maximum size of the batch in bytes.
    max_time_seconds : int
        Maximum time in seconds before a batch is sent.
    """
    def __init__(self, max_elements: int, max_size: int, max_time_seconds: int):
        self.max_elements = max_elements
        self.max_size = max_size
        self.max_time_seconds = max_time_seconds


class Batcher:
    """
    Batches messages from a MuxDemuxQueue based on size, count, or time limits.

    Parameters
    ----------
    queue : MuxDemuxQueue
        The queue from which messages are batched.
    config : BatcherConfig
        Configuration for batching limits.
    """
    def __init__(self, queue: MuxDemuxQueue, config: BatcherConfig):
        self.q: MuxDemuxQueue = queue

        self._buffer: Buffer = Buffer(max_elements=config.max_elements, max_size=config.max_size)
        self._timer: TimerManager = TimerManager(max_time_seconds=config.max_time_seconds)

    async def _get_from_queue(self) -> Message:
        """
        Retrieves a message from the mux queue asynchronously.

        Returns
        -------
        asyncio.Future[Message]
            A future that resolves to the message retrieved from the queue.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.q.receive_from_mux)

    async def _send_buffer(self, events: List[Message]):
        """
        Sends the buffered messages to the demux queue.

        Parameters
        ----------
        events : List[Message]
            The list of messages to be sent.
        """
        print(f"Batcher - Started sending - Elements {len(events)}")
        for event in events:
            self.q.send_to_demux(event)
            print(f"Batcher - Sended to demux - {event}")

    def create_flush_buffer_task(self):
        """
        Creates an asynchronous task to send the current buffer's messages and resets the buffer.
        """
        asyncio.create_task(self._send_buffer(self._buffer.copy()))
        self._buffer.reset()

    async def run(self):
        """
        Continuously retrieves messages from the queue and batches them based on the configuration.
        """
        while True:
            print("Batcher - Waiting from queue")
            done, pending = await asyncio.wait(
                [self._get_from_queue(), self._timer.wait_timeout_event()],
                return_when=asyncio.FIRST_COMPLETED
            )

            # Process completed tasks
            for task in done:
                if not isinstance(task.result(), Message):
                    print(f"Batcher - Timeout was reached")
                    # Cancel the reading task if it is still pending
                    for p_task in pending:
                        p_task.cancel()

                    self.create_flush_buffer_task()
                    self._timer.reset_timer()
                else:
                    message = task.result()
                    print(f"Batcher - Got message {message}")

                    # First message of the batch
                    if self._buffer.get_length() == 0:
                        self._timer.create_timer_task()

                    print(f"Batcher - Added message {message}")
                    self._buffer.add_message(message)

                    # Check if one of the conditions was met
                    if self._buffer.check_count_limit() or self._buffer.check_size_limit():
                        print(f"Batcher - Condition met")
                        self.create_flush_buffer_task()
                        self._timer.reset_timer()


class BatcherProcess(Process):
    """
    A multiprocessing Process that runs a Batcher to batch messages.

    Parameters
    ----------
    q : MuxDemuxQueue
        The queue from which the Batcher retrieves and sends messages.
    config : BatcherConfig
        Configuration for batching limits.
    """
    def __init__(self, q: MuxDemuxQueue, config: BatcherConfig):
        super().__init__()
        self.q = q
        self.config = config

    def run(self):
        """
        Starts the Batcher process and runs it in an asyncio event loop.
        """
        batcher = Batcher(queue=self.q, config=self.config)
        asyncio.run(batcher.run())

