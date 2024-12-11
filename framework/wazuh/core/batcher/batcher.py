import asyncio
import os
import uuid
import queue
import signal
import traceback
import logging
from typing import List, Optional
from multiprocessing import Process

from opensearchpy.exceptions import RequestError

from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.bulk import BulkDoc, Operation
from wazuh.core.indexer.models.events import Operation

from wazuh.core.batcher.buffer import Buffer
from wazuh.core.batcher.timer import TimerManager
from wazuh.core.batcher.mux_demux import MuxDemuxQueue, Item
from wazuh.core.batcher.config import BatcherConfig

logger = logging.getLogger('wazuh-comms-api')

QUEUE_READ_INTERVAL = 0.01


class Batcher:
    """Manage the batching of items from a MuxDemuxQueue and send them in bulk to an indexer.

    Parameters
    ----------
    mux_demux_queue : MuxDemuxQueue
        MuxDemuxQueue instance for item multiplexing and demultiplexing.
    config : BatcherConfig
        Configuration parameters for batching, such as maximum elements and size.
    """
    def __init__(self, mux_demux_queue: MuxDemuxQueue, config: BatcherConfig):
        self.q: MuxDemuxQueue = mux_demux_queue
        self._buffer: Buffer = Buffer(max_elements=config.max_elements, max_size=config.max_size)
        self._timer: TimerManager = TimerManager(max_time_seconds=config.max_time_seconds)
        self._shutdown_event: Optional[asyncio.Event] = None

    async def _get_from_queue(self) -> Item:
        """Retrieve an item from the mux queue. If the queue is empty, waits and retries until an item is received
        or the task is cancelled.

        Returns
        -------
        Item
            Item retrieved from the mux queue.

        Raises
        ------
        asyncio.CancelledError
            If the task is cancelled during the operation.
        """
        item = None
        while True:
            try:
                item = self.q.receive_from_mux(block=False)
                return item
            except queue.Empty:
                await asyncio.sleep(QUEUE_READ_INTERVAL)
            except asyncio.CancelledError:
                if item is not None:
                    self.q.send_to_mux(item)
                break

    async def _send_buffer(self, items: List[Item]):
        """Send a batch of items to the indexer in bulk and update the demux queue with the response items.

        Parameters
        ----------
        items : List[Item]
            List of items to be sent.

        Raises
        ------
        Exception
            If an error occurs during the sending of the buffer.
        """
        try:
            async with get_indexer_client() as indexer_client:
                bulk_list = create_bulk_list(items=items)
                response = await indexer_client.bulk(data=bulk_list)

                item_ids: List[uuid.UUID] = [item.id for item in items]
                for response_item, item_id in zip(response["items"], item_ids):
                    action_found = False

                    for operation in Operation:
                        if operation.value in response_item:
                            action_found = True
                            item = Item(id=item_id, content=response_item[operation.value], operation=operation)
                            self.q.send_to_demux(item)

                    if not action_found:
                        logger.error(f"Error processing batcher response, no known action in: {response_item}")
        except RequestError as exc:
            logger.error(f'Error sending opensearch request: {exc}')
        except Exception as e:
            tb_str = traceback.format_exception(etype=type(e), value=e, tb=e.__traceback__)
            logger.error(f"Error sending item to buffer: {''.join(tb_str)}")

    def create_flush_buffer_task(self):
        """Create a task to flush the current buffer and reset it. This task sends the buffered items to the indexer
        and clears the buffer.
        """
        buffer_copy = self._buffer.copy()
        asyncio.create_task(self._send_buffer(buffer_copy))
        self._buffer.reset()
        self._timer.reset_timer()

    async def run(self):
        """Continuously retrieve items from the queue and batch them based on the configuration. Handle signals
        for shutdown and manage the batching logic.

        Handles:
        - Retrieving items from the queue.
        - Checking buffer limits.
        - Creating and managing flush tasks.
        - Handling shutdown signals.
        """
        # Register signal handlers
        self._shutdown_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGTERM, self._handle_signal, signal.SIGTERM)
        loop.add_signal_handler(signal.SIGINT, self._handle_signal, signal.SIGINT)

        try:
            while not self._shutdown_event.is_set():
                done, pending = await asyncio.wait(
                    [self._get_from_queue(), self._timer.wait_timeout_event()],
                    return_when=asyncio.FIRST_COMPLETED
                )

                # Process completed tasks
                for task in done:
                    if isinstance(task.result(), Item):
                        item = task.result()

                        if self._buffer.get_length() == 0:
                            self._timer.create_timer_task()

                        self._buffer.add_item(item)

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
        if signal_number == signal.Signals.SIGINT:
            return
        signal_name = signal.Signals(signal_number).name
        logger.info(f'Batcher (pid: {os.getpid()}) - Received signal {signal_name}, shutting down')
        self._shutdown_event.set()


class BatcherProcess(Process):
    """Class to execute the batching in a separate process.

    Parameters
    ----------
    mux_demux_queue : MuxDemuxQueue
        MuxDemuxQueue instance for item multiplexing and demultiplexing.
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


def create_bulk_list(items: List[Item]) -> List[BulkDoc]:
    """Create a bulk list with documents depending on the operation performed."""
    docs: List[BulkDoc] = []
    for item in items:
        if item.operation == Operation.CREATE.value:
            docs.append(BulkDoc.create(index=item.index_name, doc_id=item.id, doc=item.content))    
        elif item.operation == Operation.DELETE.value:
            docs.append(BulkDoc.delete(index=item.index_name, doc_id=item.id))
        elif item.operation == Operation.UPDATE.value:
            docs.append(BulkDoc.update(index=item.index_name, doc_id=item.id, doc=item.content))

    return docs
