from __future__ import annotations

import asyncio
import time
from datetime import timedelta
from typing import Dict, Generator, List

import wazuh.core.utils as core_utils
from wazuh.core.agent import WazuhDBQueryAgents, get_agents_info
from wazuh.core.cluster import master
from wazuh.core.configuration import get_ossec_conf
from wazuh.core.exception import (
    WazuhError,
    WazuhException,
    WazuhInternalError,
    WazuhResourceNotFound,
)
from wazuh.core.indexer.indexer import get_indexer_client
from wazuh.core.results import AffectedItemsWazuhResult


class DisconnectedAgentSyncTasks:
    """
    Task to periodically synchronize group configuration for disconnected
    agents.

    This task identifies disconnected agents that have been offline for a
    minimum duration, queries the Wazuh Indexer to obtain the maximum
    version across all documents, and uses that version as external_gte
    for group synchronization.

    Attributes
    ----------
    logger : logging.Logger
        Logger instance for the task.
    server : Master
        Reference to the Master server instance.
    cluster_items : dict
        Cluster configuration with intervals and parameters.
    sync_interval : int
        Interval in seconds between task executions.
    batch_size : int
        Number of agents to process in each batch.
    min_disconnection_time : int
        Minimum time in seconds an agent must be offline to be processed.
    """

    DEFAULT_SYNC_DISCONNECT_AGENT_GROUP = 300
    DEFAULT_SYNC_DISCONNECT_AGENT_GROUPS_BATCH_SIZE = 100
    DEFAULT_SYNC_DISCONNECT_AGENT_GROUPS_MIN_OFFLINE = 600

    def __init__(
        self,
        server: master.Master = None,
        cluster_items: dict = None,
        logger: object = None,
        indexer_client: object = None,
    ):
        """
        Initialize the disconnected agent group sync task.

        Parameters
        ----------
        server : Master
            Reference to the Master server instance.
        cluster_items : dict
            Cluster configuration with intervals and parameters.
        """
        # Backwards-compatible constructor: accept either `server` (with
        # `setup_task_logger`) or `manager` + `logger` from older tests.
        if server is not None:
            self.logger = server.setup_task_logger("disconnected_agent_sync_task")
        else:
            # Fallback to a dummy logger
            import logging

            self.logger = logging.getLogger("disconnected_agent_sync_task")

        self.cluster_items = cluster_items or {}
        # Allow injecting an indexer client for tests
        self._indexer_client_override = indexer_client

        # Use from_import=True to avoid raising during tests when wazuh configuration file
        # does not contain the indexer section. The config is only used for
        # informational purposes here.
        try:
            ossec_config = get_ossec_conf(section="indexer", from_import=True)
        except Exception:
            ossec_config = {}
        self.logger.debug(f"Ossec config for indexer section: {ossec_config}")

        master_interval = cluster_items.get("intervals", {}).get("master", {})
        self.sync_interval = master_interval.get(
            "sync_disconnected_agent_groups", self.DEFAULT_SYNC_DISCONNECT_AGENT_GROUP
        )
        self.batch_size = master_interval.get(
            "sync_disconnected_agent_groups_batch_size",
            self.DEFAULT_SYNC_DISCONNECT_AGENT_GROUPS_BATCH_SIZE,
        )
        self.min_disconnection_time = master_interval.get(
            "sync_disconnected_agent_groups_min_offline",
            self.DEFAULT_SYNC_DISCONNECT_AGENT_GROUPS_MIN_OFFLINE,
        )
        self.initial_delay = master_interval.get(
            "sync_disconnected_agent_cluster_name_delay", 300
        )

        # Flag to ensure cluster-name sync runs only once per process lifecycle
        self._cluster_name_sync_done = False

    async def run_agent_groups_sync(self) -> None:
        """
        Main task loop for non-connected agent group synchronization.

        This method runs indefinitely, executing the synchronization logic
        at the defined interval.
        """
        self.logger.info(
            f"Starting non-connected agent group synchronization task "
            f"(interval: {self.sync_interval}s, batch_size: {self.batch_size})"
        )

        while True:
            try:
                cycle_start_time = time.time()
                processed_agents = 0
                failed_agents = 0

                disconnected_agents = (
                    await self._get_disconnected_agents_filter_by_time()
                )
                disconnected_agents_count = len(disconnected_agents)
                if disconnected_agents_count == 0:
                    self.logger.info("No disconnected agents found")
                    await asyncio.sleep(self.sync_interval)
                    continue

                self.logger.info(
                    f"Found {disconnected_agents_count} disconnected agents to synchronize"
                )

                for batch in self._batch_agents(disconnected_agents):
                    try:
                        batch_result = await self._sync_agent_batch(batch)
                        processed_agents += batch_result.get("processed", 0)
                        failed_agents += batch_result.get("failed", 0)
                    except Exception as e:
                        self.logger.error(
                            f"Error syncing batch of agents: {e}", exc_info=True
                        )
                        failed_agents += len(batch)

                cycle_elapsed_time = time.time() - cycle_start_time
                self.logger.info(
                    f"Finished group synchronization task. "
                    f"Processed {processed_agents}/{disconnected_agents_count} "
                    f"agents in {cycle_elapsed_time:.2f} seconds. "
                    f"{failed_agents} agents failed."
                )

            except Exception as e:
                self.logger.error(
                    f"Error in disconnected agent sync task: {e}", exc_info=True
                )
            finally:
                await asyncio.sleep(self.sync_interval)

    async def _get_disconnected_agents_filter_by_time(self) -> List[dict]:
        """
        Retrieve non-connected agents filtered by disconnection time at DB level.

        This method queries the Wazuh database for agents whose status is not
        'active', normalizes their last heartbeat timestamp to UTC, and filters
        them based on a minimum disconnection threshold.

        Returns
        -------
        List[dict]
            A list of dictionaries, where each dictionary contains the
            following agent information:
            - id : str
            - name : str
            - status : str
            - lastKeepAlive : datetime
            - dataAdd : datetime
            - group : list

        Raises
        ------
        Exception
            If there is an error during the database query or the
            processing of agent data.

        Notes
        -----
        The filtering rules applied are:
        1. status must be in ('disconnected', 'pending', 'never connected').
        2. Agents without 'lastKeepAlive' are included by default (handled
           within the normalization logic if applicable).
        3. The time since 'lastKeepAlive' plus `min_disconnection_time` must
           be less than the current UTC time.

        Inside this method, an internal helper `_normalize_to_utc` is used to
        ensure all datetime comparisons are offset-aware (UTC), avoiding
        TypeErrors when comparing naive vs aware datetimes.
        """
        try:
            agents_not_active: List[str] = await self._get_disconnected_agents()
            agents = []
            now_utc = core_utils.get_utc_now()
            for agent in agents_not_active:
                disconnected_time = agent.get("lastKeepAlive", None) or agent.get("dateAdd")
                if (
                    disconnected_time + timedelta(seconds=self.min_disconnection_time)
                    < now_utc
                ):
                    agents.append(agent)

            self.logger.info(
                f"Retrieved {len(agents)} non-active agents from WazuhDB "
                f"meeting minimum disconnection time"
            )

            return agents

        except Exception as e:
            self.logger.error(
                f"Error retrieving non-connected agents from WazuhDB: {e}",
                exc_info=True,
            )
            return []

    async def _get_max_versions_batch_from_indexer(self, agent_ids: List[str]) -> dict:
        """
        Query the Wazuh Indexer for maximum document versions of multiple agents.

        Uses a single aggregated query to fetch max versions for multiple agents,
        preventing the N+1 query problem.

        Parameters
        ----------
        agent_ids : list of str
            List of agent IDs to query.

        Returns
        -------
        dict
            Dictionary mapping agent_id to max_version (e.g., {"001": 5, "002": 3}).
        """
        if not agent_ids:
            return {}

        query = {
            "size": 0,
            "aggs": {
                "by_agent": {
                    "terms": {
                        "field": "wazuh.agent.id",
                        "include": agent_ids,
                        "exclude": ["000"],
                    },
                    "aggs": {
                        "max_document_version": {
                            "max": {"field": "state.document_version"}
                        }
                    },
                }
            },
        }

        try:
            if self._indexer_client_override:
                client = self._indexer_client_override
                result = await client.search(query=query)
            else:
                async with get_indexer_client() as client:
                    result = await client.max_version_components.search(query=query)

            max_versions = {}

            if result:
                for bucket in result["aggregations"]["by_agent"]["buckets"]:
                    agent_id = bucket.get("key")
                    max_version = bucket["max_document_version"]["value"]
                    if agent_id and max_version:
                        max_versions[agent_id] = int(max_version)
                    else:
                        raise Exception("Failed to get the max version for agent ID: " + str(agent_id))
                self.logger.info(
                    f"Batch max version query completed for {len(max_versions)} agents "
                    f"out of {len(agent_ids)} requested"
                )
                return max_versions
            else:
                raise Exception("Failed query to wazuh-indexer")

        except Exception as e:
            self.logger.exception(
                f"Failed to query max versions for batch of {len(agent_ids)} agents: {e}"
            )
            return {}

    def _batch_agents(self, agents: List[dict]) -> Generator[List[dict], None, None]:
        """
        Generate batches of agents for processing.

        Parameters
        ----------
        agents : list of dict
            List of agents to be split into batches.

        Yields
        ------
        list of dict
            A batch of agents with size less than or equal to `self.batch_size`.
        """
        for i in range(0, len(agents), self.batch_size):
            yield agents[i: i + self.batch_size]

    async def _sync_agent_batch(self, agents: List[dict]) -> dict:
        """
        Synchronize a batch of disconnected agents.

        Fetches max versions for all agents in the batch in a single call
        to prevent performance issues.

        Parameters
        ----------
        agents : list of dict
            List of agents to synchronize.

        Returns
        -------
        dict
            Dictionary with synchronization results:
            - 'processed' (int): Number of successfully processed agents.
            - 'failed' (int): Number of agents that failed synchronization.
        """
        processed = 0
        failed = 0

        agent_ids = [
            agent_info.get("id") for agent_info in agents if agent_info.get("id")
        ]

        if agent_ids:
            max_versions = await self._get_max_versions_batch_from_indexer(agent_ids)
            self.logger.debug(
                f"Batch retrieved max versions for {len(max_versions)} agents "
                f"in single indexer query"
            )
        else:
            max_versions = {}

        for agent_info in agents:
            try:
                agent_id = agent_info.get("id")
                groups = agent_info.get("group", [])

                if not agent_id or not groups:
                    self.logger.warning(
                        f"Skipping agent with incomplete info: {agent_info}"
                    )
                    failed += 1
                    continue

                external_gte = max_versions.get(agent_id, 0)

                self.logger.info(
                    f"Synchronizing groups for agent {agent_id} "
                    f"with external_gte={external_gte}, groups={groups}"
                )

                try:
                    result = await self.disconnected_agent_group_sync(
                        agent_list=[agent_id],
                        group_list=groups if isinstance(groups, list) else [groups],
                        external_gte=external_gte,
                    )
                    self.logger.debug(
                        f"Sync result for agent {agent_id}: "
                        f"affected={len(result.affected_items)},"
                        f"failed={len(result.failed_items)}"
                    )
                    processed += 1

                except Exception as e:
                    self.logger.error(
                        f"Error calling disconnected_agent_group_sync "
                        f"for agent {agent_id}: {e}"
                    )
                    failed += 1

            except Exception as e:
                self.logger.error(
                    f"Error synchronizing agent {agent_info}: {e}", exc_info=True
                )
                failed += 1

        return {"processed": processed, "failed": failed}

    async def run_cluster_name_sync(self) -> None:
        """
        One-shot task to propagate the cluster name into indexed documents
        for disconnected agents.

        Responsibilities:
        - Wait initial delay
        - Resolve disconnected agents
        - Resolve max document versions
        - Resolve current cluster names from indexer
        - Update cluster name ONLY when it differs
        """
        if self._cluster_name_sync_done:
            self.logger.debug("Cluster-name sync already executed; skipping")
            return

        try:
            self.logger.info(
                f"Waiting {self.initial_delay}s before running disconnected cluster-name sync"
            )
            await asyncio.sleep(self.initial_delay)

            disconnected_agents = await self._get_disconnected_agents()
            if not disconnected_agents:
                self.logger.info("No disconnected agents found for cluster-name sync")
                return

            agent_ids = [a["id"] for a in disconnected_agents if a.get("id")]
            if not agent_ids:
                self.logger.info("No valid agent IDs found for cluster-name sync")
                return
            # Read cluster name from ossec.conf
            try:
                conf = get_ossec_conf(section="cluster")
                cluster_name = conf.get("cluster", {}).get("name")
            except Exception as e:
                self.logger.error(f"Failed reading cluster name from ossec.conf: {e}")
                return

            if not cluster_name:
                self.logger.warning(
                    "Cluster name not found in ossec.conf; aborting sync"
                )
                return

            max_versions = await self._get_max_versions_batch_from_indexer(agent_ids)
            agent_cluster_map = await self._get_cluster_name_from_indexer(agent_ids)

            # Filter agents that actually need update
            agents_to_update = [
                agent_id
                for agent_id in agent_ids
                if agent_cluster_map.get(agent_id) != cluster_name
            ]

            if not agents_to_update:
                self.logger.info(
                    "All disconnected agents already have correct cluster name"
                )
                return
            self.logger.info(
                f"Starting Cluster name synchronization for {len(agents_to_update)} disconnected agents "
                f"with cluster_name={cluster_name}"
            )
            # Resolve indexer client once
            if self._indexer_client_override:
                client = self._indexer_client_override
                context = None
            else:
                context = get_indexer_client()

            async def _update(client):
                for agent_id in agents_to_update:
                    global_version = max_versions.get(agent_id, 0)
                    try:
                        await client.max_version_components.update_agent_cluster_name(
                            agent_id=agent_id,
                            cluster_name=cluster_name,
                            global_version=global_version,
                        )
                        self.logger.debug(
                            f"Updated cluster-name for agent={agent_id} "
                            f"version={global_version}"
                        )
                    except Exception as e:
                        self.logger.error(
                            f"Failed updating cluster-name for agent={agent_id}: {e}"
                        )

            if context:
                async with context as client:
                    await _update(client)
            else:
                await _update(client)

            self.logger.info(
                f"Disconnected agents cluster-name sync completed "
                f"({len(agents_to_update)} agents updated)"
            )

        except Exception:
            self.logger.exception("Unexpected error in run_cluster_name_sync")
        finally:
            self._cluster_name_sync_done = True

    async def disconnected_agent_group_sync(
        self, agent_list: list = None, group_list: list = None, external_gte: int = None
    ) -> AffectedItemsWazuhResult:
        """
        Synchronize group configuration for disconnected agents using external_gte version.

        Updates the Indexer with the provided group list for documents whose
        version is greater than or equal to the provided `external_gte`.

        Parameters
        ----------
        agent_list : list of str, optional
            List of disconnected agent IDs to synchronize.
        group_list : list of str, optional
            Current group list for the agent(s).
        external_gte : int, optional
            Minimum version threshold from Indexer. Documents with
            version >= external_gte will be updated.

        Returns
        -------
        AffectedItemsWazuhResult
            Synchronization result containing affected items and failed items.

        Raises
        ------
        WazuhError
            If `group_list` or `external_gte` are missing.
        WazuhResourceNotFound
            If an agent in `agent_list` does not exist in the system.
        """
        result = AffectedItemsWazuhResult(
            all_msg="Group synchronization completed for all disconnected agents",
            some_msg="Group synchronization completed for some disconnected agents",
            none_msg="No disconnected agents were synchronized",
        )

        if not agent_list:
            self.logger.debug(
                "Empty agent list provided for disconnected agent group sync"
            )
            return result

        if not group_list or external_gte is None:
            raise WazuhError(
                1001,
                extra_message="Missing required parameters: group_list, external_gte",
            )

        system_agents = get_agents_info()

        invalid_agents = []
        for agent_id in agent_list:
            if agent_id == "000":
                result.add_failed_item(id_="000", error=WazuhError(1703))
                invalid_agents.append(agent_id)
            elif agent_id not in system_agents:
                result.add_failed_item(id_=agent_id, error=WazuhResourceNotFound(1701))
                invalid_agents.append(agent_id)

        valid_agents = [a for a in agent_list if a not in invalid_agents]

        if not valid_agents:
            result.total_affected_items = 0
            return result

        self.logger.info(
            f"Starting group synchronization for {len(valid_agents)} disconnected agents "
            f"with external_gte={external_gte}"
        )

        async with get_indexer_client() as client:
            for agent_id in valid_agents:
                try:
                    await client.max_version_components.update_agent_groups(
                        agent_id=agent_id,
                        groups=group_list,
                        global_version=external_gte,
                    )
                    result.affected_items.append(agent_id)
                    self.logger.info(
                        f"Successfully synchronized agent {agent_id} "
                        f"with groups {group_list}"
                    )

                except WazuhException as e:
                    self.logger.error(f"Error synchronizing agent {agent_id}: {str(e)}")
                    result.add_failed_item(id_=agent_id, error=e)
                except Exception as e:
                    self.logger.error(
                        f"Unexpected error synchronizing agent {agent_id}: {str(e)}",
                        exc_info=True,
                    )
                    result.add_failed_item(
                        id_=agent_id,
                        error=WazuhInternalError(1000, extra_message=str(e)),
                    )

        result.total_affected_items = len(result.affected_items)
        result.affected_items.sort(key=int)

        self.logger.info(
            f"Group synchronization completed: {len(result.affected_items)} succeeded, "
            f"{len(result.failed_items)} failed"
        )

        return result

    async def _get_disconnected_agents(self) -> List[str]:
        """
        Retrieve non-connected agents from WazuhDB.

        Queries the WazuhDB for agents whose status is not `active` and
        returns the raw list of agent dictionaries as provided by the DB
        query. This helper does not apply time-based filtering; that is
        performed by `_get_disconnected_agents_filter_by_time` which calls
        this method.

        Returns
        -------
        List[dict]
            List of agent dictionaries with keys: ``id``, ``name``,
            ``status``, ``lastKeepAlive``, ``group``, and ``dateAdd``.

        Notes
        -----
        Any exception raised while querying the DB is logged and an empty
        list is returned to allow higher-level logic to continue running.
        """
        try:
            with WazuhDBQueryAgents(
                select=["id", "name", "status", "lastKeepAlive", "group", "dateAdd"],
                query="status!=active",
            ) as db_query:
                result = db_query.run()
            return result.get("items", [])
        except Exception as e:
            self.logger.error(
                f"Error retrieving non-connected agents from WazuhDB: {e}",
                exc_info=True,
            )
            return []

    async def _get_cluster_name_from_indexer(
        self, agent_ids: List[str], cluster_name: str = ""
    ) -> dict[str, str]:
        """
        Return a mapping of agent_id -> cluster_name for the given agents.

        Only agents that have an associated wazuh.cluster.name will be returned.

        Parameters
        ----------
        agent_ids : list[str]
            List of agent IDs to query.

        Returns
        -------
        dict[str, str]
            Mapping of agent_id to cluster_name.
        """
        if not agent_ids:
            return {}

        query = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"terms": {"wazuh.agent.id": agent_ids}},
                        {"exists": {"field": "wazuh.cluster.name"}},
                    ],
                    "must_not": [
                        {"term": {"wazuh.cluster.name.keyword": cluster_name}}
                    ],
                }
            },
            "aggs": {
                "by_agent": {
                    "terms": {"field": "wazuh.agent.id", "size": len(agent_ids)},
                    "aggs": {
                        "cluster_name": {
                            "terms": {"field": "wazuh.cluster.name", "size": 5}
                        }
                    },
                }
            },
        }

        try:
            if self._indexer_client_override:
                client = self._indexer_client_override
                result = await client.search(query=query)
            else:
                async with get_indexer_client() as client:
                    result = await client.max_version_components.search(query=query)
            agent_cluster_map: Dict[str, str] = {}

            buckets = (
                result.get("aggregations", {}).get("by_agent", {}).get("buckets", [])
            )

            for bucket in buckets:
                agent_id = bucket.get("key")
                cluster_buckets = bucket["cluster_name"]["buckets"]

                if not cluster_buckets:
                    continue

                if len(cluster_buckets) > 1:
                    self.logger.warning(
                        f"Agent {agent_id} belongs to multiple clusters: "
                        f"{[b['key'] for b in cluster_buckets]}"
                    )

                agent_cluster_map[agent_id] = cluster_buckets[0]["key"]

            self.logger.info(
                f"Resolved cluster name for {len(agent_cluster_map)} "
                f"out of {len(agent_ids)} requested agents"
            )
            return agent_cluster_map

        except Exception:
            self.logger.exception(
                f"Failed to resolve cluster names for agents: {agent_ids}"
            )
            return {}
