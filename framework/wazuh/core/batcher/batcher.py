import asyncio
import sys
from typing import List, Optional
from multiprocessing import Process

from mux_demux import MuxDemuxQueue, Message


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
        self.config: BatcherConfig = config

        self._buffer: List[Message] = []

        self._timeout_event = asyncio.Event()
        self._timeout_task: Optional[asyncio.Future] = None

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

    def get_buffer_len(self) -> int:
        """
        Gets the current length of the buffer.

        Returns
        -------
        int
            The number of messages currently in the buffer.
        """
        return len(self._buffer)

    def add_message_to_buffer(self, event: Message):
        """
        Adds a message to the buffer.

        Parameters
        ----------
        event : Message
            The message to be added to the buffer.
        """
        self._buffer.append(event)

    def check_buffer_count_limit(self) -> bool:
        """
        Checks if the buffer has reached the maximum number of messages.

        Returns
        -------
        bool
            True if the buffer has reached the maximum number of messages, False otherwise.
        """
        return self.get_buffer_len() >= self.config.max_elements

    def check_buffer_size_limit(self) -> bool:
        """
        Checks if the buffer has reached the maximum size in bytes.

        Returns
        -------
        bool
            True if the buffer has reached the maximum size, False otherwise.
        """
        total_size = sum(sys.getsizeof(msg.msg) for msg in self._buffer)
        return total_size >= self.config.max_size

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
        self.reset_buffer()

    async def _event_timer(self):
        """
        Asynchronous timer that waits for the configured max time before setting the timeout event.
        """
        await asyncio.sleep(self.config.max_time_seconds)
        self._timeout_event.set()

    def create_timer_task(self):
        """
        Creates an asynchronous task to start the event timer.
        """
        self._timeout_task = asyncio.create_task(self._event_timer())

    def reset_timer(self):
        """
        Resets the timer by canceling the current timer task (if any) and clearing the timeout event.
        """
        if self._timeout_task is not None:
            self._timeout_task.cancel()
            self._timeout_task = None
        self._timeout_event.clear()

    def reset_buffer(self):
        """
        Clears the buffer.
        """
        self._buffer.clear()

    async def run(self):
        """
        Continuously retrieves messages from the queue and batches them based on the configuration.
        """
        while True:
            print("Batcher - Waiting from queue")
            done, pending = await asyncio.wait(
                [self._get_from_queue(), self._timeout_event.wait()],
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
                    self.reset_timer()
                else:
                    message = task.result()
                    print(f"Batcher - Got message {message}")

                    # First message of the batch
                    if self.get_buffer_len() == 0:
                        self.create_timer_task()

                    print(f"Batcher - Added message {message}")
                    self.add_message_to_buffer(message)

                    # Check if one of the conditions was met
                    if self.check_buffer_size_limit() or self.check_buffer_count_limit():
                        print(f"Batcher - Condition met")
                        self.create_flush_buffer_task()
                        self.reset_timer()


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

