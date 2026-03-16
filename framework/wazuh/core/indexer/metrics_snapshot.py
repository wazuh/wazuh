import asyncio
import logging


class MetricsSnapshotTasks:
    DEFAULT_METRICS_FREQUENCY = 600
    DEFAULT_METRICS_BULK_SIZE = 100

    def __init__(self, server, cluster_items: dict):
        self.server = server
        if server is not None and hasattr(server, "setup_task_logger"):
            self.logger = server.setup_task_logger("metrics_snapshot")
        else:
            self.logger = logging.getLogger("wazuh")

        master_interval = cluster_items.get("intervals", {}).get("master", {})
        if "metrics_frequency" not in master_interval:
            self.logger.warning(
                f"metrics_frequency not found in cluster configuration. Using default: {self.DEFAULT_METRICS_FREQUENCY}"
            )

        if "metrics_bulk_size" not in master_interval:
            self.logger.warning(
                f"metrics_bulk_size not found in cluster configuration. Using default: {self.DEFAULT_METRICS_BULK_SIZE}"
            )

        self.frequency = master_interval.get(
            "metrics_frequency", self.DEFAULT_METRICS_FREQUENCY
        )
        self.bulk_size = master_interval.get(
            "metrics_bulk_size", self.DEFAULT_METRICS_BULK_SIZE
        )

    async def run_metrics_snapshot(self):
        while True:
            if self.frequency == 0:
                self.logger.info("Metrics snapshot is disabled (metrics_frequency=0).")
                return
            await asyncio.sleep(max(self.frequency, self.DEFAULT_METRICS_FREQUENCY))
            try:
                await self._collect_and_index()
            except Exception:
                self.logger.exception("Metrics snapshot failed - skipping cycle")

    async def _collect_and_index(self):
        pass  # TODO:
