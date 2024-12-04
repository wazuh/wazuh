import os
import logging
import signal
from multiprocessing import Queue, Process, Event
from multiprocessing.managers import DictProxy, SyncManager
from typing import Any


logger = logging.getLogger('wazuh-comms-api')


class Item:
    """Item for the MuxDemuxQueue with an associated unique identifier.

    Parameters
    ----------
    id : int
        Unique identifier for the item.
    operation : str
        Kind of operation to perform. Can be either 'create', 'delete' or 'update'.
    content : dict
        Item content as a dictionary. Can be either a stateful event, a response from OpenSearch or None.
    index_name : str
        Name of the index the item should be created in. Should be set when inserting an item to the mux_queue only.
    """
    def __init__(self, id: int, operation: str, content: dict = None, index_name: str = None):
        self.id = id
        self.content = content
        self.operation = operation
        self.index_name = index_name


class MuxDemuxQueue:
    """Class for managing items between mux and demux components.

    Parameters
    ----------
    proxy_dict : DictProxy
        Dictionary-like proxy for managing responses.
    mux_queue : Queue
        Queue for multiplexing items.
    demux_queue : Queue
        Queue for demultiplexing items.
    """
    def __init__(self, proxy_dict: DictProxy, mux_queue: Queue, demux_queue: Queue):
        self.responses = proxy_dict
        self.mux_queue = mux_queue
        self.demux_queue = demux_queue

    def send_to_mux(self, item: Item):
        """Put a item into the mux queue with an associated unique identifier.

        Parameters
        ----------
        item : Item
            Item to be put into the mux queue.
        """
        self.mux_queue.put(item)

    def receive_from_mux(self, block: bool = True) -> Item:
        """Retrieve a item from the mux queue. If the queue
        is empty and block is False it raises a queue.Empty error.

        Returns
        -------
        Item
            Item retrieved from the mux queue.
        """
        return self.mux_queue.get(block=block)

    def send_to_demux(self, item: Item):
        """Put a item into the demux queue.

        Parameters
        ----------
        item : Item
            Item to be put into the demux queue.
        """
        self.demux_queue.put(item)

    def is_response_pending(self, item_id: int) -> bool:
        """Check if a response is available for a given unique identifier.

        Parameters
        ----------
        item_id : int
            Unique identifier to check.

        Returns
        -------
        bool
            True if response is available, False otherwise.
        """
        return item_id not in self.responses

    def receive_from_demux(self, item_id: int) -> dict:
        """Retrieve and remove a response from the dictionary for a given unique identifier.

        Parameters
        ----------
        item_id : int
            Unique identifier of the response.

        Returns
        -------
        dict
            Indexer response.
        """
        response = self.responses[item_id]
        del self.responses[item_id]
        return response

    def internal_get_response_from_demux(self) -> Item:
        """Retrieve an item from the demux queue.

        Returns
        -------
        Item
            Item retrieved from the demux queue.
        """
        return self.demux_queue.get()

    def internal_store_response(self, item: Item):
        """Update the responses dictionary with the item content.

        Parameters
        ----------
        item : Item
            Item whose content will be added to the response dictionary.
        """
        if item.id not in self.responses:
            self.responses[item.id] = [item.content]
        else:
            # Using self.responses[item.id].append() doesn't work because
            # it doesn't hold the reference of nested objects
            responses = self.responses[item.id]
            responses.append(item.content)
            self.responses[item.id] = responses


class MuxDemuxRunner(Process):
    """Multiprocessing Process in charge of managing the MuxDemuxQueue operations, handling
    signals for graceful shutdown and processing items from the queue.

    The MuxDemuxRunner class runs as a separate process to manage the `MuxDemuxQueue`. It listens
    for termination signals to initiate a graceful shutdown, and continuously
    processes items from the queue, storing them as responses if they are of the correct type.
    """

    def __init__(self, queue: MuxDemuxQueue):
        super().__init__()
        self.queue = queue
        self._shutdown_event = Event()

    def _handle_signal(self, signum: int, frame: Any):
        """Handle termination signals by setting the shutdown event.

        Parameters
        ----------
        signum : int
            Signal number received.
        frame : Any
            Current stack frame (unused).
        """
        signal_name = signal.Signals(signum).name
        logger.info(f'MuxDemuxQueue (pid: {os.getpid()}) - Received signal {signal_name}, shutting down')
        self._shutdown_event.set()

    def run(self) -> None:
        """Main loop of the process. Set up signal handling, and process items from
        the queue until the shutdown event is set.

        This method registers signal handlers for SIGTERM and SIGINT to gracefully terminate the
        process. It continuously checks the queue for new items, and stores responses if the items
        are of type `Item`. On encountering an exception, it logs the error and checks the
        shutdown status to decide whether to continue or terminate.
        """
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        while not self._shutdown_event.is_set():
            try:
                item = self.queue.internal_get_response_from_demux()
                if isinstance(item, Item):
                    self.queue.internal_store_response(item)
            except Exception as e:
                if self._shutdown_event.is_set():
                    return
                else:
                    logger.error(f'Error with MuxDemuxQueue run: {e}', exc_info=True)


class MuxDemuxManager:
    """Manage the lifecycle and interactions with MuxDemuxQueue and its processes.

    The MuxDemuxManager handles the creation, management, and shutdown of the MuxDemuxQueue
    and its associated process.
    """
    def __init__(self):
        SyncManager.register('MuxDemuxQueue', MuxDemuxQueue)
        self.manager = SyncManager()
        self.manager.start()

        self.queue = self.manager.MuxDemuxQueue(
            self.manager.dict(),
            self.manager.Queue(),
            self.manager.Queue()
        )
        self.queue_process = MuxDemuxRunner(queue=self.queue)
        self.queue_process.start()

    def get_manager(self) -> SyncManager:
        """Return the SyncManager instance.

        Returns
        -------
        SyncManager
            SyncManager instance.
        """
        return self.manager

    def get_queue_process(self) -> Process:
        """Return the MuxDemuxQueue process instance.

        Returns
        -------
        Process
            Process instance running the MuxDemuxQueue demux.
        """
        return self.queue_process

    def get_queue(self) -> MuxDemuxQueue:
        """Return the MuxDemuxQueue instance.

        Returns
        -------
        MuxDemuxQueue
            MuxDemuxQueue instance.
        """
        return self.queue

    def shutdown(self):
        """Terminate the MuxDemuxQueue process and shuts down the SyncManager."""
        self.queue_process.terminate()
        self.manager.shutdown()
