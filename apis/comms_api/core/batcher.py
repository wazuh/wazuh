from typing import Optional

from wazuh.core.batcher.mux_demux import MuxDemuxQueue, MuxDemuxManager
from wazuh.core.batcher.batcher import BatcherConfig, BatcherProcess

batcher_mux_demux_manager: Optional[MuxDemuxManager] = None
batcher_process: Optional[BatcherProcess] = None


def create_batcher_process(config: BatcherConfig):
    global batcher_mux_demux_manager, batcher_process

    batcher_mux_demux_manager = MuxDemuxManager()
    batcher_process = BatcherProcess(
        q=batcher_mux_demux_manager.get_queue(),
        config=config,
    )
    batcher_process.start()
