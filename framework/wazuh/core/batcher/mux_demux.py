import uuid

from multiprocessing import Queue, Process
from multiprocessing.managers import DictProxy, SyncManager
from typing import Optional


class Message:
    """
    A message for the MuxDemuxQueue with an associated unique identifier.

    Parameters
    ----------
    uid : str
        The unique identifier for the message.
    msg : dict
        The message content as a dictionary.
    """
    def __init__(self, uid: str, msg: dict):
        self.uid = uid
        self.msg = msg


class MuxDemuxQueue:
    """
    A queue for managing messages between mux and demux components.

    Parameters
    ----------
    proxy_dict : DictProxy
        A dictionary-like proxy for managing responses.
    q_mux : Queue
        The queue for multiplexing messages.
    q_demux : Queue
        The queue for demultiplexing messages.
    """
    def __init__(self, proxy_dict: DictProxy, q_mux: Queue, q_demux: Queue):
        self.responses = proxy_dict
        self.q_mux = q_mux
        self.q_demux = q_demux

    def send_to_mux(self, uid: uuid.UUID, msg: dict) -> uuid.UUID:
        """
        Puts a message into the mux queue with an associated unique identifier.

        Parameters
        ----------
        uid : uuid.UUID
            The unique identifier for the message.
        msg : dict
            The message content to be put into the mux queue.

        Returns
        -------
        uuid.UUID
            The unique identifier of the message.
        """
        msg = Message(uid=uid, msg=msg)
        self.q_mux.put(msg)
        return uid

    def receive_from_mux(self) -> Message:
        """
        Retrieves a message from the mux queue.

        Returns
        -------
        Message
            The message retrieved from the mux queue.
        """
        return self.q_mux.get()

    def send_to_demux(self, msg: Message):
        """
        Puts a message into the demux queue.

        Parameters
        ----------
        msg : Message
            The message to be put into the demux queue.
        """
        self.q_demux.put(msg)

    def is_response_pending(self, uid: uuid.UUID) -> bool:
        """
        Checks if a response is available for a given unique identifier.

        Parameters
        ----------
        uid : uuid.UUID
            The unique identifier to check.

        Returns
        -------
        bool
            True if the response is available, False otherwise.
        """
        return uid not in self.responses

    def receive_from_demux(self, uid: uuid.UUID) -> Optional[dict]:
        """
        Retrieves and removes a response from the dictionary for a given unique identifier.

        Parameters
        ----------
        uid : uuid.UUID
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

    def run(self):
        """
        Continuously retrieves messages from the demux queue and updates the responses.
        """

        while True:
            item = self._get_response_from_demux()
            print(f'Router process Recv: {item.__dict__}')
            if isinstance(item, Message):
                self._store_response(item)

    def _get_response_from_demux(self) -> Message:
        """
        Retrieves a message from the demux queue.

        Returns
        -------
        Message
            The message retrieved from the demux queue.
        """
        return self.q_demux.get()

    def _store_response(self, msg: Message):
        """
        Updates the responses dictionary with the message content.

        Parameters
        ----------
        msg : Message
            The message whose content will be added to the responses dictionary.
        """
        self.responses[msg.uid] = msg.msg


class MuxDemuxManager:
    """
    Manages the lifecycle and interactions with MuxDemuxQueue and its processes.

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

        self.router = self.manager.MuxDemuxQueue(
            self.manager.dict(),
            self.manager.Queue(),
            self.manager.Queue()
        )
        self.router_process = Process(target=self.router.run, args=())
        self.router_process.start()

    def get_manager(self) -> SyncManager:
        """
        Returns the SyncManager instance.

        Returns
        -------
        SyncManager
            The SyncManager instance.
        """
        return self.manager

    def get_router_process(self) -> Process:
        """
        Returns the MuxDemuxQueue process instance.

        Returns
        -------
        Process
            The Process instance running the MuxDemuxQueue demux.
        """
        return self.router_process

    def get_router(self) -> MuxDemuxQueue:
        """
        Returns the MuxDemuxQueue instance.

        Returns
        -------
        MuxDemuxQueue
            The MuxDemuxQueue instance.
        """
        return self.router

    def shutdown(self):
        """
        Terminates the MuxDemuxQueue process and shuts down the SyncManager.
        """
        self.router_process.terminate()
        self.manager.shutdown()
