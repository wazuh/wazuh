import asyncio
import logging
from wazuh.core.agent import WazuhDBQueryAgents

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

    def _get_agents_sync(self):
        query = WazuhDBQueryAgents(limit=None)
        return query.run()["items"]

    async def _collect_agents(self, timestamp: str):
        loop = asyncio.get_running_loop()

        agents_data = await loop.run_in_executor(None, self._get_agents_sync)
        node_name = self.server.configuration.get("node_name", "unknown")
        node_type = self.server.configuration.get("node_type", "master")

        for agent in agents_data:
            agent["@timestamp"] = timestamp
            agent["wazuh.cluster.node_name"] = node_name
            agent["wazuh.cluster.node_type"] = node_type

        return agents_data

    async def _collect_and_index(self):
        pass  # TODO:
