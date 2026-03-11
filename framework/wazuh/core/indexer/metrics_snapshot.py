import asyncio
import logging

logger = logging.getLogger("wazuh")


class MetricsSnapshotTasks:
    def __init__(self, server, cluster_items: dict):
        master_interval = cluster_items.get("intervals", {}).get("master", {})
        if "metrics_frequency" not in master_interval:
            logger.warning(
                "metrics_frequency not found in cluster configuration. Using default: 600"
            )

        if "metrics_bulk_size" not in master_interval:
            logger.warning(
                "metrics_bulk_size not found in cluster configuration. Using default: 100"
            )

        self.frequency = master_interval.get("metrics_frequency", 600)
        self.bulk_size = master_interval.get("metrics_bulk_size", 100)
        self.server = server

    async def run_metrics_snapshot(self):
        while True:
            if self.frequency == 0:
                return
            await asyncio.sleep(max(self.frequency, 600))
            try:
                await self._collect_and_index()
            except Exception:
                logger.exception("Metrics snapshot failed - skipping cycle")

    async def _collect_and_index(self):
        pass  # TODO:
