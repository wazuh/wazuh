import asyncio
from multiprocessing import Process

from wazuh.core.batcher.mux_demux import MuxDemuxQueue, MuxDemuxManager
from wazuh.core.batcher.batcher import BatcherConfig, BatcherProcess
from wazuh.core.batcher.client import BatcherClient


async def sender_worker(worker_id: int, client: BatcherClient):
    list_of_ids = []
    for i in range(10):
        event = {'id': worker_id, 'msg': f'Message from {worker_id} - Number {i}'}
        assigned_id = client.send_event(event)
        list_of_ids.append(assigned_id)

    for i in list_of_ids:
        result = await client.get_response(i)
        print(f'Worker {worker_id} - Recv {result}')

    print(f'Worker {worker_id} - FINISHED')


def run_worker(worker_id: int, queue: MuxDemuxQueue):
    client = BatcherClient(queue=queue)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(sender_worker(worker_id, client))


if __name__ == "__main__":
    queue_manager = MuxDemuxManager()
    queue = queue_manager.get_router()
    queue_process = queue_manager.get_router_process()

    config = BatcherConfig(max_elements=6, max_size=30000, max_time_seconds=5)
    batcher_process = BatcherProcess(q=queue, config=config)
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
