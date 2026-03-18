import asyncio
import logging
from wazuh.core.agent import WazuhDBQueryAgents

from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.stats import get_daemons_stats


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

    async def _collect_comms_all_nodes(self, timestamp: str) -> list:
        """Collect wazuh-remoted stats from all cluster nodes via DAPI fan-out.

        Parameters
        ----------
        timestamp : str
            ISO 8601 timestamp to inject into each document as ``@timestamp``.

        Returns
        -------
        list of dict
            Documents ready for bulk indexing into ``wazuh-metrics-comms``.
            Each document contains the remoted stats fields plus the metadata
            fields ``@timestamp``, ``wazuh.cluster.node_name``, and
            ``wazuh.cluster.node_type``.
        """
        local_node_name = self.server.configuration.get("node_name", "unknown")
        local_node_type = self.server.configuration.get("node_type", "master")

        all_nodes = {local_node_name: local_node_type}
        for worker_name, worker_handler in self.server.clients.items():
            worker_type = worker_handler.get_node().get("type", "worker")
            all_nodes[worker_name] = worker_type

        comms_data = []
        for node_name, node_type in all_nodes.items():
            try:
                result = await DistributedAPI(
                    f=get_daemons_stats,
                    f_kwargs={
                        "daemons_list": ["wazuh-manager-remoted"],
                        "node_list": [node_name],
                    },
                    logger=self.logger,
                    request_type="distributed_master",
                    is_async=False,
                    wait_for_complete=True,
                ).distribute_function()

                for item in getattr(result, "affected_items", []):
                    doc = dict(item)
                    doc["@timestamp"] = timestamp
                    doc["wazuh.cluster.node_name"] = node_name
                    doc["wazuh.cluster.node_type"] = node_type
                    comms_data.append(doc)
            except Exception:
                self.logger.exception(
                    "Failed to collect comms stats from node '%s'", node_name
                )

        return comms_data

    async def _collect_and_index(self):
        pass  # TODO:
