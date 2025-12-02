# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it
# under the terms of GPLv2

import asyncio
import logging
import time
from typing import List, Optional

from opensearchpy import AsyncOpenSearch

from wazuh.core.indexer.base import BaseIndex
from wazuh.core.wdb import AsyncWazuhDBConnection

# Index patterns that should be excluded from synchronization operations
EXCLUDED_INDEX_PATTERN_MONITORING = "wazuh-monitoring-*"
EXCLUDED_INDEX_PATTERN_STATISTICS = "wazuh-statistics-*"
EXCLUDED_INDEX_PATTERNS = [
    EXCLUDED_INDEX_PATTERN_MONITORING,
    EXCLUDED_INDEX_PATTERN_STATISTICS,
]

# Index patterns for agent states (all data related to agent status)
AGENT_STATE_INDEX_PATTERN = "wazuh-states-*"


class DisconnectedAgentGroupSyncTask(BaseIndex):
    """
    Task to periodically synchronize group configuration for disconnected
    agents.

    This task:
    1. Identifies disconnected agents that have been offline for a minimum
    duration
    2. Queries the Wazuh Indexer to obtain the maximum version across all
    documents
    3. Uses that version as external_gte for group synchronization
    4. Ensures indexed data remains consistent with current group
    configuration
    """

    def __init__(
        self,
        manager: "Master",
        logger: logging.Logger,
        cluster_items: dict,
        indexer_client: Optional[AsyncOpenSearch] = None,
    ):
        """Initialize the disconnected agent group sync task.

        Parameters
        ----------
        manager : Master
            Reference to the Master server instance
        logger : logging.Logger
            Logger instance for the task
        cluster_items : dict
            Cluster configuration with intervals and parameters
        indexer_client : AsyncOpenSearch, optional
            OpenSearch/Elasticsearch client for querying the Indexer
        """
        # Initialize parent class
        super().__init__(client=indexer_client)

        self.manager = manager
        self._logger = logger
        self.cluster_items = cluster_items

        # Configuration parameters
        master_interval = cluster_items.get("intervals", {}).get("master", {})
        self.sync_interval = master_interval.get("sync_disconnected_agent_groups",
                                                 300)
        self.batch_size = master_interval.get(
            "sync_disconnected_agent_groups_batch_size", 100
        )
        self.min_disconnection_time = master_interval.get(
            "sync_disconnected_agent_groups_min_offline", 600
        )
        self.enabled = cluster_items.get("disconnected_agent_sync", {}).get(
            "enabled", True
        )
        self.indexes = [AGENT_STATE_INDEX_PATTERN]

    async def run(self) -> None:
        """Main task loop for Non-connected agent group synchronization."""
        if not self.enabled:
            self._logger.info("Non-connected agent group sync task is disabled")
            return

        self._logger.info(
            f"Starting non-connected agent group synchronization task "
            f"(interval: {self.sync_interval}s, batch_size: {self.batch_size})"
        )

        wdb_conn = AsyncWazuhDBConnection()

        while True:
            try:
                # Record start time for performance tracking
                cycle_start_time = time.time()
                processed_agents = 0
                failed_agents = 0
                
                # Get non-connected agents
                disconnected_agents = await self._get_disconnected_agents(wdb_conn)

                if not disconnected_agents:
                    self._logger.debug(
                        "No disconnected agents found for synchronization"
                    )
                    await asyncio.sleep(self.sync_interval)
                    continue

                self._logger.info(
                    f"Found {len(disconnected_agents)} disconnected agents to synchronize"
                )

                # Process agents in batches
                for batch in self._batch_agents(disconnected_agents):
                    try:
                        batch_result = await self._sync_agent_batch(batch)
                        processed_agents += batch_result.get("processed", 0)
                        failed_agents += batch_result.get("failed", 0)
                    except Exception as e:
                        self._logger.error(
                            f"Error syncing batch of agents: {e}", exc_info=True
                        )
                        failed_agents += len(batch)

                # Log summary of the synchronization cycle
                cycle_elapsed_time = time.time() - cycle_start_time
                total_agents = len(disconnected_agents)
                self._logger.info(
                    f"Finished group synchronization task. "
                    f"Processed {processed_agents}/{total_agents} agents in {cycle_elapsed_time:.2f} seconds. "
                    f"{failed_agents} agents failed."
                )

            except Exception as e:
                self._logger.error(
                    f"Error in disconnected agent sync task: {e}", exc_info=True
                )
            finally:
                await asyncio.sleep(self.sync_interval)

    async def _get_disconnected_agents(
        self, wdb_conn: AsyncWazuhDBConnection
    ) -> List[dict]:
        """Get list of non-connected agents from WazuhDB.

        Parameters
        ----------
        wdb_conn : AsyncWazuhDBConnection
            WazuhDB connection instance

        Returns
        -------
        List[dict]
            List of non-connected agents with their information
        """
        try:
            # Query agents with disconnected status using get_agents_overview
            from wazuh.core.agent import (
                Agent,
            )  # Import here to avoid circular dependency

            agents_data = Agent.get_agents_overview(
                filters={
                    "status": ["disconnected, never_connected, pending"],
                },
                limit=None,
                get_data=True,
            )

            all_agents = agents_data.get("data", {}).get("affected_items", [])
            
            # Filter agents by minimum disconnection time
            current_time = int(time.time())
            filtered_agents = []
            
            for agent in all_agents:
                disconnection_time = agent.get("disconnection_time", 0)
                time_disconnected = current_time - disconnection_time
                
                if time_disconnected >= self.min_disconnection_time:
                    filtered_agents.append(agent)
                    self._logger.debug(
                        f"Agent {agent.get('id')} included: disconnected for {time_disconnected}s "
                        f"(min required: {self.min_disconnection_time}s)"
                    )
                else:
                    self._logger.debug(
                        f"Agent {agent.get('id')} filtered out: disconnected for {time_disconnected}s "
                        f"(min required: {self.min_disconnection_time}s)"
                    )

            self._logger.debug(
                f"Retrieved {len(all_agents)} non-connected agents from WazuhDB, "
                f"filtered to {len(filtered_agents)} agents meeting min disconnection time"
            )
            return filtered_agents

        except Exception as e:
            self._logger.error(
                f"Error retrieving non-connected agents from WazuhDB: {e}",
                exc_info=True
            )
            return []

    async def _get_max_versions_batch_from_indexer(self, agent_ids: List[str]) -> dict:
        """Query the Wazuh Indexer for maximum document versions of multiple agents.

        This method uses a single aggregated query to fetch max versions for multiple
        agents, preventing the N+1 query problem that occurs when querying agents
        individually.

        Parameters
        ----------
        agent_ids : List[str]
            List of agent IDs to query

        Returns
        -------
        dict
            Dictionary mapping agent_id to max_version (e.g., {"001": 5, "002": 3})
        """
        if not self._client:
            self._logger.warning("Indexer client not available, skipping batch version query")
            return {}

        if not agent_ids:
            return {}

        # Build aggregation query based on number of agents
        if len(agent_ids) == 1:
            # For single agent, use a simple max aggregation
            query = {
                "size": 0,
                "aggs": {
                    "max_version": {"max": {"field": "state.document_version"}}
                },
                "query": {
                    "bool": {
                        "must": [{"term": {"agent.id": agent_ids[0]}}]
                    }
                },
            }
        else:
            # For multiple agents, group by agent.id
            query = {
                "size": 0,
                "aggs": {
                    "by_agent": {
                        "terms": {"field": "agent.id", "size": len(agent_ids)},
                        "aggs": {"max_version": {"max": {"field": "state.document_version"}}},
                    }
                },
                "query": {
                    "bool": {
                        "must": [{"terms": {"agent.id": agent_ids}}]
                    }
                },
            }

        try:
            result = await self._client.search(
                index=",".join(self.indexes), body=query, request_timeout=30
            )

            # Extract max versions by agent from aggregation results
            max_versions = {}
            
            if len(agent_ids) == 1:
                # Handle single agent response
                max_version = (
                    result.get("aggregations", {})
                    .get("max_version", {})
                    .get("value")
                )
                if max_version is not None:
                    max_versions[agent_ids[0]] = int(max_version)
                else:
                    self._logger.debug(
                        f"No version found for agent {agent_ids[0]} in indexer"
                    )
            else:
                # Handle multiple agent response
                buckets = (
                    result.get("aggregations", {})
                    .get("by_agent", {})
                    .get("buckets", [])
                )
                for bucket in buckets:
                    agent_id = bucket.get("key")
                    max_version = bucket.get("max_version", {}).get("value")
                    if agent_id and max_version is not None:
                        max_versions[agent_id] = int(max_version)

            self._logger.debug(
                f"Batch max version query completed for {len(max_versions)} agents "
                f"out of {len(agent_ids)} requested"
            )
            return max_versions

        except Exception as e:
            self._logger.warning(
                f"Failed to query max versions for batch of {len(agent_ids)} agents: {e}"
            )
            return {}

    async def _get_max_version_from_indexer(self, agent_id: str) -> int:
        """Query the Wazuh Indexer for maximum document version of an agent.

        Parameters
        ----------
        agent_id : str
            ID of the agent

        Returns
        -------
        int
            Maximum version found in all documents, or 0 if not found
        """
        max_versions = await self._get_max_versions_batch_from_indexer([agent_id])
        return max_versions.get(agent_id, 0)

    def _batch_agents(self, agents: List[dict]):
        """Generate batches of agents for processing.

        Parameters
        ----------
        agents : List[dict]
            List of agents

        Yields
        ------
        List[dict]
            Batches of agents with size <= self.batch_size
        """
        for i in range(0, len(agents), self.batch_size):
            yield agents[i: i + self.batch_size]

    async def _sync_agent_batch(self, agents: List[dict]) -> dict:
        """Synchronize a batch of disconnected agents.

        Uses batch query to fetch max versions for all agents at once, preventing
        N+1 query problem.

        Parameters
        ----------
        agents : List[dict]
            List of agents to synchronize

        Returns
        -------
        dict
            Dictionary with sync results containing:
            - 'processed': number of successfully processed agents
            - 'failed': number of agents that failed synchronization
        """
        from wazuh import agent as agent_module

        processed = 0
        failed = 0

        # Extract agent IDs and fetch all max versions in a single batch query
        agent_ids = [
            agent_info.get("id")
            for agent_info in agents
            if agent_info.get("id")
        ]

        if agent_ids:
            # Single aggregated query for all agents instead of N individual queries
            max_versions = await self._get_max_versions_batch_from_indexer(agent_ids)
            self._logger.debug(
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
                    self._logger.warning(
                        f"Skipping agent with incomplete info: {agent_info}"
                    )
                    failed += 1
                    continue

                # Use pre-fetched max version from batch query
                external_gte = max_versions.get(agent_id, 0)

                self._logger.info(
                    f"Synchronizing groups for agent {agent_id} "
                    f"with external_gte={external_gte}, groups={groups}"
                )

                # Call disconnected_agent_group_sync function
                try:
                    result = await agent_module.disconnected_agent_group_sync(
                        agent_list=[agent_id],
                        group_list=groups if isinstance(groups, list) else [groups],
                        external_gte=external_gte,
                    )

                    self._logger.debug(
                        f"Sync result for agent {agent_id}: "
                        f"affected={len(result.affected_items)},"
                        f"failed={len(result.failed_items)}"
                    )
                    processed += 1

                except Exception as e:
                    self._logger.error(
                        f"Error calling disconnected_agent_group_sync for "
                        f"agent {agent_id}: {e}"
                    )
                    failed += 1

            except Exception as e:
                self._logger.error(
                    f"Error synchronizing agent {agent_info}: {e}",
                    exc_info=True
                )
                failed += 1

        return {"processed": processed, "failed": failed}
