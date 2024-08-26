import asyncio
import uuid
from typing import List, Optional
from multiprocessing import Process
import queue
import signal
import traceback
import logging

from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.bulk import BulkDoc

from wazuh.core.batcher.buffer import Buffer
from wazuh.core.batcher.timer import TimerManager
from wazuh.core.batcher.mux_demux import MuxDemuxQueue, Message
from wazuh.core.batcher.config import BatcherConfig

logger = logging.getLogger('wazuh-comms-api')

WAIT_TIME_BETWEEN_QUEUE_READ = 0.01


class Batcher:
    """
    Manages the batching of messages from a MuxDemuxQueue and sends them in bulk to an indexer.

    Parameters
    ----------
    queue : MuxDemuxQueue
        The MuxDemuxQueue instance for message multiplexing and demultiplexing.
    config : BatcherConfig
        Configuration parameters for batching, such as maximum elements and size.
    """
    def __init__(self, queue: MuxDemuxQueue, config: BatcherConfig):
        self.q: MuxDemuxQueue = queue
        self._buffer: Buffer = Buffer(max_elements=config.max_elements, max_size=config.max_size)
        self._timer: TimerManager = TimerManager(max_time_seconds=config.max_time_seconds)
        self._shutdown_event: Optional[asyncio.Event] = None

    async def _get_from_queue(self) -> Message:
        """
        Retrieves a message from the mux queue. If the queue is empty, waits and retries until a message is received
        or the task is cancelled.

        Returns
        -------
        Message
            The message retrieved from the mux queue.

        Raises
        ------
        asyncio.CancelledError
            If the task is cancelled during the operation.
        """
        message = None
        while True:
            try:
                message = self.q.receive_from_mux(block=False)
                return message
            except queue.Empty:
                await asyncio.sleep(WAIT_TIME_BETWEEN_QUEUE_READ)
            except asyncio.CancelledError:
                if message is not None:
                    self.q.send_to_mux(uid=message.uid, msg=message.msg)
                break

    async def _send_buffer(self, events: List[Message]):
        """
        Sends a batch of messages to the indexer in bulk. Updates the demux queue with the response messages.

        Parameters
        ----------
        events : List[Message]
            The list of messages to be sent in bulk.

        Raises
        ------
        Exception
            If an error occurs during the sending of the buffer.
        """
        try:
            async with get_indexer_client() as indexer_client:
                list_of_uid: List[uuid.UUID] = [event.uid for event in events]
                bulk_list: List[BulkDoc] = [
                    BulkDoc.create(index=indexer_client.events.INDEX, doc_id=None, doc=event.msg) for event in events
                ]

                response = await indexer_client.events.bulk(data=bulk_list)

                for response_item, uid in zip(response["items"], list_of_uid):
                    response_item_msg = response_item["create"]
                    response_msg = Message(uid=uid, msg=response_item_msg)
                    self.q.send_to_demux(response_msg)
        except Exception as e:
            tb_str = traceback.format_exception(etype=type(e), value=e, tb=e.__traceback__)
            logger.error(f"Error when sending buffer:\n{''.join(tb_str)}")

    def create_flush_buffer_task(self):
        """
        Creates a task to flush the current buffer and reset it. This task sends the buffered messages to the indexer
        and clears the buffer.
        """
        buffer_copy = self._buffer.copy()
        asyncio.create_task(self._send_buffer(buffer_copy))
        self._buffer.reset()

    async def run(self):
        """
        Continuously retrieves messages from the queue and batches them based on the configuration. Handles signals
        for shutdown and manages the batching logic.

        Handles:
        - Retrieving messages from the queue.
        - Checking buffer limits.
        - Creating and managing flush tasks.
        - Handling shutdown signals.
        """
        # Register signal handlers
        self._shutdown_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, self._handle_signal, signal.SIGINT)
        loop.add_signal_handler(signal.SIGTERM, self._handle_signal, signal.SIGTERM)

        try:
            while not self._shutdown_event.is_set():
                done, pending = await asyncio.wait(
                    [self._get_from_queue(), self._timer.wait_timeout_event()],
                    return_when=asyncio.FIRST_COMPLETED
                )

                # Process completed tasks
                for task in done:
                    if isinstance(task.result(), Message):
                        message = task.result()

                        if self._buffer.get_length() == 0:
                            self._timer.create_timer_task()

                        self._buffer.add_message(message)

                        if self._buffer.check_count_limit() or self._buffer.check_size_limit():
                            self.create_flush_buffer_task()
                            self._timer.reset_timer()
                    else:
                        # Cancel the reading task if it is still pending
                        for p_task in pending:
                            p_task.cancel()

                        self.create_flush_buffer_task()
                        self._timer.reset_timer()

        except Exception as e:
            tb_str = traceback.format_exception(etype=type(e), value=e, tb=e.__traceback__)
            logger.error(f"Error in batcher loop:\n{''.join(tb_str)}")
        finally:
            # Ensure all tasks are properly cancelled
            for task in asyncio.all_tasks():
                if task is not asyncio.current_task():
                    task.cancel()
            await asyncio.gather(*asyncio.all_tasks(), return_exceptions=True)

    def _handle_signal(self, signal_number):
        """
        Handles shutdown signals by setting the shutdown event.

        Parameters
        ----------
        signal_number : int
            The signal number indicating the type of signal received (e.g., SIGINT, SIGTERM).
        """
        logger.info(f"Batcher - Received signal {signal_number}, initiating shutdown.")
        self._shutdown_event.set()


class BatcherProcess(Process):
    """
    A process that runs a Batcher instance. This class is used to execute the Batcher in a separate process.

    Parameters
    ----------
    q : MuxDemuxQueue
        The MuxDemuxQueue instance for message multiplexing and demultiplexing.
    config : BatcherConfig
        Configuration parameters for batching, such as maximum elements and size.
    """
    def __init__(self, q: MuxDemuxQueue, config: BatcherConfig):
        super().__init__()
        self.q = q
        self.config = config

    def run(self):
        """
        Initializes and runs a Batcher instance in the process. This method is called when the process is started.
        """
        batcher = Batcher(queue=self.q, config=self.config)
        asyncio.run(batcher.run())
