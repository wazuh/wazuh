import asyncio
import os
import uuid
import queue
import signal
import traceback
import logging
from typing import List, Optional
from multiprocessing import Process

from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.bulk import BulkDoc, BulkAction

from wazuh.core.batcher.buffer import Buffer
from wazuh.core.batcher.timer import TimerManager
from wazuh.core.batcher.mux_demux import MuxDemuxQueue, Message
from wazuh.core.batcher.config import BatcherConfig

logger = logging.getLogger('wazuh-comms-api')

QUEUE_READ_INTERVAL = 0.01


class Batcher:
    """Manage the batching of messages from a MuxDemuxQueue and send them in bulk to an indexer.

    Parameters
    ----------
    mux_demux_queue : MuxDemuxQueue
        MuxDemuxQueue instance for message multiplexing and demultiplexing.
    config : BatcherConfig
        Configuration parameters for batching, such as maximum elements and size.
    """
    def __init__(self, mux_demux_queue: MuxDemuxQueue, config: BatcherConfig):
        self.q: MuxDemuxQueue = mux_demux_queue
        self._buffer: Buffer = Buffer(max_elements=config.max_elements, max_size=config.max_size)
        self._timer: TimerManager = TimerManager(max_time_seconds=config.max_time_seconds)
        self._shutdown_event: Optional[asyncio.Event] = None

    async def _get_from_queue(self) -> Message:
        """Retrieve a message from the mux queue. If the queue is empty, waits and retries until a message is received
        or the task is cancelled.

        Returns
        -------
        Message
            Message retrieved from the mux queue.

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
                await asyncio.sleep(QUEUE_READ_INTERVAL)
            except asyncio.CancelledError:
                if message is not None:
                    self.q.send_to_mux(uid=message.uid, msg=message.msg)
                break

    async def _send_buffer(self, events: List[Message]):
        """Send a batch of messages to the indexer in bulk and update the demux queue with the response messages.

        Parameters
        ----------
        events : List[Message]
            List of messages to be sent.

        Raises
        ------
        Exception
            If an error occurs during the sending of the buffer.
        """
        try:
            async with get_indexer_client() as indexer_client:
                event_ids: List[uuid.UUID] = [event.uid for event in events]
                bulk_list: List[BulkDoc] = [
                    BulkDoc.create(index=indexer_client.events.INDEX, doc_id=None, doc=event.msg) for event in events
                ]

                response = await indexer_client.events.bulk(data=bulk_list)

                for response_item, uid in zip(response["items"], event_ids):
                    action_found = False

                    for action in BulkAction:
                        if action.value in response_item:
                            action_found = True
                            response_item_msg = response_item[action.value]
                            response_msg = Message(uid=uid, msg=response_item_msg)
                            self.q.send_to_demux(response_msg)

                    if not action_found:
                        logger.error(f"Error processing batcher response, no known action in: {response_item}")
        except Exception as e:
            tb_str = traceback.format_exception(etype=type(e), value=e, tb=e.__traceback__)
            logger.error(f"Error sending message to buffer: {''.join(tb_str)}")

    def create_flush_buffer_task(self):
        """Create a task to flush the current buffer and reset it. This task sends the buffered messages to the indexer
        and clears the buffer.
        """
        buffer_copy = self._buffer.copy()
        asyncio.create_task(self._send_buffer(buffer_copy))
        self._buffer.reset()
        self._timer.reset_timer()

    async def run(self):
        """Continuously retrieve messages from the queue and batch them based on the configuration. Handle signals
        for shutdown and manage the batching logic.

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
                    else:
                        # Cancel the reading task if it is still pending
                        for p_task in pending:
                            p_task.cancel()

                        self.create_flush_buffer_task()

        except Exception as e:
            tb_str = traceback.format_exception(etype=type(e), value=e, tb=e.__traceback__)
            logger.error(f"Error in batcher loop:{''.join(tb_str)}")
        finally:
            # Ensure all tasks are properly cancelled
            for task in asyncio.all_tasks():
                if task is not asyncio.current_task():
                    task.cancel()
            await asyncio.gather(*asyncio.all_tasks(), return_exceptions=True)

    def _handle_signal(self, signal_number: int):
        """Handle shutdown signals by setting the shutdown event.

        Parameters
        ----------
        signal_number : int
            Signal number indicating the type of signal received (e.g., SIGINT, SIGTERM).
        """
        logger.info(f'Batcher pid {os.getpid()} - Received signal {signal_number}, initiating shutdown.')
        self._shutdown_event.set()


class BatcherProcess(Process):
    """Class to execute the batching in a separate process.

    Parameters
    ----------
    mux_demux_queue : MuxDemuxQueue
        MuxDemuxQueue instance for message multiplexing and demultiplexing.
    config : BatcherConfig
        Configuration parameters for batching, such as maximum elements and size.
    """
    def __init__(self, mux_demux_queue: MuxDemuxQueue, config: BatcherConfig):
        super().__init__()
        self.queue = mux_demux_queue
        self.config = config

    def run(self):
        """
        Initialize and run a Batcher instance in the process. This method is called when the process is started.
        """
        batcher = Batcher(mux_demux_queue=self.queue, config=self.config)
        asyncio.run(batcher.run())
