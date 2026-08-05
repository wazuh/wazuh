# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Dict, List, Optional

from opensearchpy import AsyncOpenSearch
from wazuh.core.indexer.base import IndexerKey

AGENT_STATS_INDEX = "wazuh-agent-stats"


class AgentStatsIndex:
    """
    Indexer client for the statistics agents report over `POST /stats`.

    One live document per agent, whose id is the agent id: every push replaces the previous one, so
    there is no history to page through and a read is an access by key.
    """

    def __init__(self, client: AsyncOpenSearch) -> None:
        """
        Initialize the AgentStatsIndex.

        Parameters
        ----------
        client : AsyncOpenSearch
            Asynchronous OpenSearch client used to perform index operations.
        """
        super().__init__()
        self._client = client

    async def get_component(self, agent_ids: List[str], component: str) -> Dict[str, Optional[dict]]:
        """
        Read one component's statistics for several agents in a single request.

        Uses `mget` with `_source` trimmed to the requested component, so only that subtree crosses
        the wire. The manager normalizes the agent's `modules` array into an object keyed by module
        name before indexing, which is what makes this a single field access rather than a search
        through an array.

        Parameters
        ----------
        agent_ids : List[str]
            Agent IDs to read. Each one is also its document id.
        component : str
            Component to return, as spelled in the API's `component` enum (`agent`, `logcollector`).

        Returns
        -------
        Dict[str, Optional[dict]]
            Agent ID to that component's statistics, or None when the agent has no document or the
            document carries no such component. Every requested ID is present in the mapping.
        """
        response = await self._client.mget(
            index=AGENT_STATS_INDEX,
            body={IndexerKey.IDS.value: agent_ids},
            _source=[f"wazuh.agent.statistics.{component}"],
        )

        found = {
            document.get(IndexerKey._ID.value):
                (document.get(IndexerKey._SOURCE.value) or {})
                .get("wazuh", {})
                .get("agent", {})
                .get("statistics", {})
                .get(component)
            for document in response.get(IndexerKey.DOCS.value, [])
            if document.get(IndexerKey.FOUND.value)
        }

        # An empty component is not the same as a missing one, but neither is usable as stats, so
        # both collapse to None and the caller falls back to querying the agent.
        return {agent_id: found.get(agent_id) or None for agent_id in agent_ids}
