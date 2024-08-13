import asyncio
import os
from multiprocessing import Process

from wazuh.core.batcher.mux_demux import MuxDemuxQueue, MuxDemuxManager
from wazuh.core.batcher.batcher import BatcherConfig, BatcherProcess, IndexerConfig
from wazuh.core.batcher.client import BatcherClient


INDEXER_HOST = os.environ.get('WAZUH_INDEXER_HOST', '127.0.0.1')
INDEXER_PORT = os.environ.get('WAZUH_INDEXER_PORT', 9200)
INDEXER_USER = os.environ.get('WAZUH_INDEXER_USER', 'admin')
INDEXER_PASSWORD = os.environ.get('WAZUH_INDEXER_PASSWORD', 'SecretPassword1%')


async def sender_worker(worker_id: int, client: BatcherClient):
    list_of_ids = []
    for i in range(10):
        event = {'id': worker_id, 'msg': f'Message from {worker_id} - Number {i}'}
        uid = f'{worker_id}_{i}'
        assigned_id = client.send_event(uid, event)
        list_of_ids.append(assigned_id)

    for i in list_of_ids:
        result = await client.get_response(i)
        print(f'Worker {worker_id} - Recv {result}')

    print(f'Worker {worker_id} - FINISHED')


def run_worker(worker_id: int, queue: MuxDemuxQueue):
    client = BatcherClient(queue=queue)
    asyncio.run(sender_worker(worker_id, client))


async def main():
    indexer_config = IndexerConfig(host=INDEXER_HOST, user=INDEXER_USER, password=INDEXER_PASSWORD, port=INDEXER_PORT)

    queue_manager = MuxDemuxManager()
    queue = queue_manager.get_router()

    config = BatcherConfig(max_elements=6, max_size=30000, max_time_seconds=5)
    batcher_process = BatcherProcess(q=queue, config=config, indexer_config=indexer_config)
    batcher_process.start()

    list_of_senders = []
    for i in range(4):
        list_of_senders.append(Process(target=run_worker, args=(i, queue)))

    for i in list_of_senders:
        i.start()

    for i in list_of_senders:
        i.join()

    batcher_process.join()
    queue_manager.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
