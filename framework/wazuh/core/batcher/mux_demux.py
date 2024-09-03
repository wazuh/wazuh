import os
import logging
import signal
from multiprocessing import Queue, Process, Event
from multiprocessing.managers import DictProxy, SyncManager
from typing import Optional, Any


logger = logging.getLogger('wazuh-comms-api')


class Message:
    """A message for the MuxDemuxQueue with an associated unique identifier.

    Parameters
    ----------
    uid : int
        The unique identifier for the message.
    msg : dict
        The message content as a dictionary.
    """
    def __init__(self, uid: int, msg: dict):
        self.uid = uid
        self.msg = msg


class MuxDemuxQueue:
    """A queue for managing messages between mux and demux components.

    Parameters
    ----------
    proxy_dict : DictProxy
        A dictionary-like proxy for managing responses.
    mux_queue : Queue
        The queue for multiplexing messages.
    demux_queue : Queue
        The queue for demultiplexing messages.
    """
    def __init__(self, proxy_dict: DictProxy, mux_queue: Queue, demux_queue: Queue):
        self.responses = proxy_dict
        self.mux_queue = mux_queue
        self.demux_queue = demux_queue

    def send_to_mux(self, uid: int, msg: dict) -> int:
        """Puts a message into the mux queue with an associated unique identifier.

        Parameters
        ----------
        uid : int
            The unique identifier for the message.
        msg : dict
            The message content to be put into the mux queue.

        Returns
        -------
        int
            The unique identifier of the message.
        """
        msg = Message(uid=uid, msg=msg)
        self.mux_queue.put(msg)
        return uid

    def receive_from_mux(self, block: bool = True) -> Message:
        """Retrieves a message from the mux queue. f the queue
        is empty and block is False it raises an queue.Empty error

        Returns
        -------
        Message
            The message retrieved from the mux queue.
        """
        message = self.mux_queue.get(block=block)
        return message

    def send_to_demux(self, msg: Message):
        """Puts a message into the demux queue.

        Parameters
        ----------
        msg : Message
            The message to be put into the demux queue.
        """
        self.demux_queue.put(msg)

    def is_response_pending(self, uid: int) -> bool:
        """Checks if a response is available for a given unique identifier.

        Parameters
        ----------
        uid : int
            The unique identifier to check.

        Returns
        -------
        bool
            True if the response is available, False otherwise.
        """
        return uid not in self.responses

    def receive_from_demux(self, uid: int) -> Optional[dict]:
        """Retrieves and removes a response from the dictionary for a given unique identifier.

        Parameters
        ----------
        uid : int
            The unique identifier for the response.

        Returns
        -------
        Optional[dict]
            The response dictionary if available, None otherwise.
        """
        if not self.is_response_pending(uid):
            response = self.responses[uid]
            del self.responses[uid]
            return response
        else:
            return None

    def internal_response_from_demux(self) -> Message:
        """Retrieves a message from the demux queue.

        Returns
        -------
        Message
            The message retrieved from the demux queue.
        """
        return self.demux_queue.get()

    def internal_store_response(self, msg: Message):
        """Updates the responses dictionary with the message content.

        Parameters
        ----------
        msg : Message
            The message whose content will be added to the responses dictionary.
        """
        self.responses[msg.uid] = msg.msg


class MuxDemuxRunner(Process):
    """A multiprocessing Process that manages the MuxDemuxQueue operations, handling
    signals for graceful shutdown and processing items from the queue.

    The MuxDemuxRunner class runs as a separate process to manage the `MuxDemuxQueue`. It listens
    for termination signals (SIGTERM, SIGINT) to initiate a graceful shutdown, and continuously
    processes items from the queue, storing them as responses if they are of the correct type.
    """

    def __init__(self, queue: MuxDemuxQueue):
        super().__init__()
        self.queue = queue
        self._shutdown_event = Event()

    def _handle_signal(self, signum: int, frame: Any):
        """Handles termination signals (SIGTERM, SIGINT) by setting the shutdown event.

        Parameters
        ----------
        signum : int
            The signal number received.
        frame : Any
            The current stack frame (unused).
        """
        logger.info(f'MuxDemuxQueue pid {os.getpid()} - received signal {signum}')
        self._shutdown_event.set()

    def run(self) -> None:
        """Main loop of the process. Sets up signal handling, and processes items from
        the queue until the shutdown event is set.

        This method registers signal handlers for SIGTERM and SIGINT to gracefully terminate the
        process. It continuously checks the queue for new items, and stores responses if the items
        are of type `Message`. On encountering an exception, it logs the error and checks the
        shutdown status to decide whether to continue or terminate.
        """
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        while not self._shutdown_event.is_set():
            try:
                item = self.queue.internal_response_from_demux()
                if isinstance(item, Message):
                    self.queue.internal_store_response(item)
            except Exception as e:
                if self._shutdown_event.is_set():
                    logger.info(f'MuxDemuxQueue pid {os.getpid()} - shutting down')
                    return
                else:
                    logger.error(f'Error with MuxDemuxQueue run: {e}', exc_info=True)


class MuxDemuxManager:
    """Manages the lifecycle and interactions with MuxDemuxQueue and its processes.

    The MuxDemuxManager handles the creation, management, and shutdown of the MuxDemuxQueue
    and its associated process.

    Parameters
    ----------
    None
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
        """Returns the SyncManager instance.

        Returns
        -------
        SyncManager
            The SyncManager instance.
        """
        return self.manager

    def get_queue_process(self) -> Process:
        """Returns the MuxDemuxQueue process instance.

        Returns
        -------
        Process
            The Process instance running the MuxDemuxQueue demux.
        """
        return self.queue_process

    def get_queue(self) -> MuxDemuxQueue:
        """Returns the MuxDemuxQueue instance.

        Returns
        -------
        MuxDemuxQueue
            The MuxDemuxQueue instance.
        """
        return self.queue

    def shutdown(self):
        """Terminates the MuxDemuxQueue process and shuts down the SyncManager."""
        self.queue_process.terminate()
        self.manager.shutdown()
