from wazuh.core.batcher.mux_demux import MuxDemuxQueue, MuxDemuxManager
from wazuh.core.batcher.batcher import BatcherConfig, BatcherProcess


def create_batcher_process(config: BatcherConfig) -> (MuxDemuxManager, BatcherProcess):
    """Creates and starts a batcher process with the provided configuration.

    Parameters
    ----------
    config : BatcherConfig
        The configuration settings for the batcher process.

    Returns
    -------
    tuple(MuxDemuxManager, BatcherProcess)
        A tuple containing the MuxDemuxManager and the started BatcherProcess.
    """
    batcher_mux_demux_manager = MuxDemuxManager()
    batcher_process = BatcherProcess(
        queue=batcher_mux_demux_manager.get_queue(),
        config=config,
    )
    batcher_process.start()

    return batcher_mux_demux_manager, batcher_process
