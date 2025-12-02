# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it
# under the terms of GPLv2

import asyncio
import logging
from typing import List, Optional

from opensearchpy import AsyncOpenSearch

from wazuh.core.indexer.base import BaseIndex
from wazuh.core.wdb import AsyncWazuhDBConnection


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
                # Get non-connected agents
                disconnected_agents = await self._get_non_connected_agents(wdb_conn)

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
                        await self._sync_agent_batch(batch)
                    except Exception as e:
                        self._logger.error(
                            f"Error syncing batch of agents: {e}", exc_info=True
                        )

            except Exception as e:
                self._logger.error(
                    f"Error in disconnected agent sync task: {e}", exc_info=True
                )
            finally:
                await asyncio.sleep(self.sync_interval)

    async def _get_non_connected_agents(
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
                    "older_than": self.min_disconnection_time,
                },
                limit=None,
                get_data=True,
            )

            agents = agents_data.get("data", {}).get("affected_items", [])

            self._logger.debug(
                f"Retrieved {len(agents)} non-connected agents from WazuhDB"
            )
            return agents

        except Exception as e:
            self._logger.error(
                f"Error retrieving non-connected agents from WazuhDB: {e}"
            )
            return []

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
        if not self._client:
            self._logger.warning("Indexer client not available, skipping version query")
            return 0

        # Indices to search
        indices = [
            "wazuh-states-*",
        ]

        # Build aggregation query
        query = {
            "size": 0,
            "aggs": {"max_version": {"max": {"field": "state.document_version"}}},
            "query": {"bool": {"must": [{"term": {"agent.id": agent_id}}]}},
        }

        try:
            result = await self._client.search(
                index=",".join(indices), body=query, request_timeout=30
            )

            max_version = (
                result.get("aggregations", {}).get("max_version", {}).get("value")
            )

            if max_version is not None:
                self._logger.debug(f"Max version for agent {agent_id}: {max_version}")
                return int(max_version)
            else:
                self._logger.debug(
                    f"No documents found for agent {agent_id} in indexer"
                )
                return 0

        except Exception as e:
            self._logger.warning(
                f"Failed to query max version for agent {agent_id}: {e}"
            )
            return 0

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

    async def _sync_agent_batch(self, agents: List[dict]) -> None:
        """Synchronize a batch of disconnected agents.

        Parameters
        ----------
        agents : List[dict]
            List of agents to synchronize
        """
        from wazuh import agent as agent_module

        for agent_info in agents:
            try:
                agent_id = agent_info.get("id")
                groups = agent_info.get("group", [])

                if not agent_id or not groups:
                    self._logger.warning(
                        f"Skipping agent with incomplete info: {agent_info}"
                    )
                    continue

                # Get maximum version from Indexer
                external_gte = await self._get_max_version_from_indexer(agent_id)

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

                except Exception as e:
                    self._logger.error(
                        f"Error calling disconnected_agent_group_sync for "
                        f"agent {agent_id}: {e}"
                    )

            except Exception as e:
                self._logger.error(
                    f"Error synchronizing agent {agent_info}: {e}",
                    exc_info=True
                )
