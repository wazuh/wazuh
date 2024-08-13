import asyncio
from typing import List
from multiprocessing import Process

from wazuh.core.indexer import Indexer, create_indexer
from wazuh.core.indexer.bulk import BulkDoc

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


class IndexerConfig:
    """Configuration for the Indexer connection.

    Parameters
    ----------
    host : str
        Location of the Wazuh Indexer.
    user : str, optional
        User of the Wazuh Indexer to authenticate with.
    password : str, optional
        Password of the Wazuh Indexer to authenticate with.
    port : int, optional
        Port of the Wazuh Indexer to connect with, by default 9200
    """
    def __init__(self,  host: str, user: str = '', password: str = '', port: int = 9200):
        self.host = host
        self.user = user
        self.password = password
        self.port = port


class Batcher:
    """
    Batches messages from a MuxDemuxQueue based on size, count, or time limits.

    Parameters
    ----------
    queue : MuxDemuxQueue
        The queue from which messages are batched.
    config : BatcherConfig
        Configuration for batching limits.
    indexer_config : IndexerConfig
        Configuration to connect with Wazuh Indexer
    """
    def __init__(self, queue: MuxDemuxQueue, config: BatcherConfig, indexer_config: IndexerConfig):
        self.q: MuxDemuxQueue = queue
        self.indexer_config = indexer_config

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
        indexer = await create_indexer(
            host=self.indexer_config.host,
            user=self.indexer_config.user,
            password=self.indexer_config.password,
            use_ssl=False
        )

        bulk_list: List[BulkDoc] = []
        for event in events:
            bulk_list.append(BulkDoc.create(index=indexer.events.INDEX, doc_id=event.uid, doc=event.msg))

        print(f"Batcher - Started sending - Elements {len(bulk_list)}")
        response = await indexer.events.bulk(data=bulk_list)

        print(f"Batcher - Received response from Indexer - {response}")
        for response_item in response["items"]:
            response_item_msg = response_item["create"]

            response_msg = Message(uid=response_item_msg["_id"], msg=response_item_msg)
            self.q.send_to_demux(response_msg)
            print(f"Batcher - Sended to demux - {response_msg}")

        await indexer.close()

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
    indexer_config : IndexerConfig
        Configuration to connect with Wazuh Indexer
    """
    def __init__(self, q: MuxDemuxQueue, config: BatcherConfig, indexer_config: IndexerConfig):
        super().__init__()
        self.q = q
        self.config = config
        self.indexer_config = indexer_config

    def run(self):
        """
        Starts the Batcher process and runs it in an asyncio event loop.
        """
        batcher = Batcher(queue=self.q, config=self.config, indexer_config=self.indexer_config)
        asyncio.run(batcher.run())
