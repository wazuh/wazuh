import os
import logging
import signal
import sys
from multiprocessing import Queue, Process, Event
from multiprocessing.managers import DictProxy, SyncManager
from typing import Any

from wazuh.core.indexer.models.events import AgentMetadata, Header, get_module_index_name


logger = logging.getLogger('wazuh-comms-api')


class Item:
    """Item for the MuxDemuxQueue with an associated unique identifier.

    Parameters
    ----------
    id : int
        Unique identifier for the item.
    operation : str
        Kind of operation to perform. Can be either 'create', 'delete' or 'update'.
    content : bytes
        Item content as bytes. Can be either a stateful event, a response from OpenSearch or None.
    index_name : str
        Name of the index the item should be created in. Should be set when inserting an item to the mux_queue only.
    """
    def __init__(self, id: int, operation: str, content: bytes = None, index_name: str = None):
        self.id = id
        self.content = content
        self.operation = operation
        self.index_name = index_name


class Packet:
    """Class for managing and processing packets containing multiple items.

    Parameters
    ----------
    id : int, optional
        Identifier for the packet. Defaults to None.
    items : list[Item], optional
        List of items included in the packet. Defaults to an empty list.
    """
    def __init__(self, id: int = None, items: list[Item] = None):
        if items is None:
            items = []
        self.id: None | int = id
        self.items: list[Item] = items

    def add_id(self, id: int):
        """Sets the packet's identifier.

        Parameters
        ----------
        id : int
            Identifier to be assigned to the packet.
        """
        self.id = id

    def has_item(self, id: int) -> bool:
        """Checks if the packet contains an item with the specified identifier.

        Parameters
        ----------
        id : int
            Identifier of the item to check.

        Returns
        -------
        bool
            True if the item is found, False otherwise.
        """
        for item in self.items:
            if item.id == id:
                return True
        return False

    def get_len(self) -> int:
        """Returns the number of items in the packet.

        Returns
        -------
        int
            Number of items in the packet.
        """
        return len(self.items)

    def get_size(self) -> int:
        """Calculates the total size of all items' content in the packet.

        Returns
        -------
        int
            Total size of all items' content in bytes.
        """
        return sum(sys.getsizeof(item.content) for item in self.items)

    def build_and_add_item(self, agent_metadata: AgentMetadata, header: Header, data: bytes = None):
        """Builds an item using metadata, header, and optional data, then adds it to the packet.

        Parameters
        ----------
        agent_metadata : AgentMetadata
            Metadata about the agent to include in the item's content.
        header : Header
            Header information for the item.
        data : bytes, optional
            Optional additional data to include in the item's content. Defaults to None.
        """
        content = None
        if data is not None:
            content = self.build_content(agent_metadata.model_dump_json().encode(), data)

        item = Item(
            id=header.id,
            operation=header.operation,
            content=content,
            index_name=get_module_index_name(header.module, header.type)
        )
        self.add_item(item)

    def add_item(self, item: Item):
        """Adds an item to the packet. If the packet has no identifier, sets it using the item's ID.

        Parameters
        ----------
        item : Item
            The item to add to the packet.
        """
        if len(self.items) == 0 and self.id is None:
            self.id = item.id

        self.items.append(item)
    
    def build_content(self, agent_metadata: bytes, data: bytes = None) -> bytes:
        """Build event body.
        
        Parameters
        ----------
        agent_metadata : bytes
            Agent metadata.
        data : bytes
            Event data.
        
        Returns
        -------
        bytes
            Agent metadata and event joined.
        """
        return b'{' + agent_metadata[1:-1] + b', ' + data[1:-1] + b'}'


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
        self._subscriptions = {}

    def send_to_mux(self, packet: Packet):
        """Put a packet into the mux queue with an associated unique identifier.

        Parameters
        ----------
        packet : Packet
            Packet to be put into the mux queue.
        """
        self.mux_queue.put(packet)

    def receive_from_mux(self, block: bool = True) -> Packet:
        """Retrieve a packet from the mux queue. If the queue
        is empty and block is False it raises a queue.Empty error.

        Returns
        -------
        Packet
            Packet retrieved from the mux queue.
        """
        return self.mux_queue.get(block=block)

    def send_to_demux(self, packet: Packet):
        """Put a packet into the demux queue.

        Parameters
        ----------
        packet : Packet
            Packet to be put into the demux queue.
        """
        self.demux_queue.put(packet)

    def is_response_pending(self, packet_id: int) -> bool:
        """Check if a response is available for a given unique identifier.

        Parameters
        ----------
        packet_id : int
            Unique identifier to check.

        Returns
        -------
        bool
            True if response is available, False otherwise.
        """
        return packet_id not in self.responses

    def receive_from_demux(self, packet_id: int) -> Packet:
        """Retrieve and remove a response from the dictionary for a given unique identifier.

        Parameters
        ----------
        packet_id : int
            Unique identifier of the response.

        Returns
        -------
        dict
            Indexer response.
        """
        if self.is_response_pending(packet_id):
            event = Event()
            self._subscriptions.update({packet_id: event})

            event.wait(10)
            self._subscriptions.pop(packet_id, None)

        response = self.responses[packet_id]
        del self.responses[packet_id]
        return response

    def internal_get_response_from_demux(self) -> Packet:
        """Retrieve an item from the demux queue.

        Returns
        -------
        Packet
            Packet retrieved from the demux queue.
        """
        return self.demux_queue.get()

    def internal_store_response(self, packet: Packet):
        """Update the responses dictionary with the item content.

        Parameters
        ----------
        packet : Packet
            Packet whose content will be added to the response dictionary.
        """
        if packet.id not in self.responses:
            self.responses[packet.id] = packet
        else:
            # Using self.responses[packet.id].append() doesn't work because
            # it doesn't hold the reference of nested objects
            response = self.responses[packet.id]
            response.items.extend(packet.items)
            self.responses[packet.id] = response

        if packet.id in self._subscriptions:
            self._subscriptions[packet.id].set()


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
        logger.info(f'MuxDemuxRunner (pid: {os.getpid()}) - Received signal {signal_name}, shutting down')
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
                packet = self.queue.internal_get_response_from_demux()
                self.queue.internal_store_response(packet)
            except EOFError:
                # Mux demux manager queue closed, exit
                logger.info('Shutting down MuxDemuxRunner')
                return
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
