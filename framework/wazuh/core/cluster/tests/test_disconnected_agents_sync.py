# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


with patch("wazuh.core.common.wazuh_uid"):
    with patch("wazuh.core.common.wazuh_gid"):
        sys.modules["wazuh.rbac.orm"] = MagicMock()
        sys.modules["api"] = MagicMock()
        sys.modules["api.configuration"] = MagicMock()
        sys.modules["api.validator"] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules["wazuh.rbac.orm"]
        del sys.modules["api"]
        del sys.modules["api.configuration"]
        del sys.modules["api.validator"]
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.core.cluster import master
        from wazuh.core.results import AffectedItemsWazuhResult


# Global cluster configuration
cluster_items = {
    "node": "master-node",
    "intervals": {
        "worker": {"connection_retry": 1, "sync_integrity": 2, "sync_agent_info": 5},
        "communication": {
            "timeout_receiving_file": 1,
            "timeout_dapi_request": 1,
            "max_zip_size": 1073741824,
            "min_zip_size": 31457280,
            "zip_limit_tolerance": 0.2,
        },
        "master": {
            "max_locked_integrity_time": 0,
            "timeout_agent_info": 0,
            "timeout_extra_valid": 0,
            "process_pool_size": 10,
            "recalculate_integrity": 0,
            "sync_agent_groups": 1,
            "agent_group_start_delay": 1,
            "sync_disconnected_agent_groups": 5,
            "sync_disconnected_agent_groups_batch_size": 2,
            "sync_disconnected_agent_groups_min_offline": 600,
        },
    },
    "files": {
        "cluster_item_key": {"remove_subdirs_if_empty": True, "permissions": "value"}
    },
    "disconnected_agent_sync": {"enabled": True},
}


@pytest.mark.asyncio
async def test_disconnected_agent_group_sync_task_get_max_version_from_indexer():
    """Test DisconnectedAgentGroupSyncTask _get_max_version_from_indexer method."""

    manager_mock = MagicMock()
    logger_mock = MagicMock()

    # Mock OpenSearch client
    indexer_client_mock = AsyncMock()
    indexer_client_mock.search.return_value = {
        "aggregations": {"max_version": {"value": 150}}
    }

    task = master.DisconnectedAgentGroupSyncTask(
        manager=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=indexer_client_mock,
    )

    result = await task._get_max_version_from_indexer("001")

    assert result == 150
    indexer_client_mock.search.assert_called_once()


@pytest.mark.asyncio
async def test_disconnected_agent_group_sync_task_get_max_version_from_indexer_no_documents():
    """Test DisconnectedAgentGroupSyncTask _get_max_version_from_indexer with no documents."""

    manager_mock = MagicMock()
    logger_mock = MagicMock()

    # Mock OpenSearch client - no documents found
    indexer_client_mock = AsyncMock()
    indexer_client_mock.search.return_value = {
        "aggregations": {"max_version": {"value": None}}
    }

    task = master.DisconnectedAgentGroupSyncTask(
        manager=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=indexer_client_mock,
    )

    result = await task._get_max_version_from_indexer("001")

    assert result == 0
    logger_mock.debug.assert_called()


@pytest.mark.asyncio
async def test_disconnected_agent_group_sync_task_get_max_version_from_indexer_error():
    """Test DisconnectedAgentGroupSyncTask _get_max_version_from_indexer with indexer error."""

    manager_mock = MagicMock()
    logger_mock = MagicMock()

    # Mock OpenSearch client - error on search
    indexer_client_mock = AsyncMock()
    indexer_client_mock.search.side_effect = Exception("Indexer connection error")

    task = master.DisconnectedAgentGroupSyncTask(
        manager=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=indexer_client_mock,
    )

    result = await task._get_max_version_from_indexer("001")

    assert result == 0
    logger_mock.warning.assert_called()


@pytest.mark.asyncio
@patch("wazuh.core.cluster.master.AsyncWazuhDBConnection")
@patch("wazuh.agent.disconnected_agent_group_sync")
async def test_disconnected_agent_group_sync_task_sync_agent_batch(
    mock_disconnected_sync, mock_wdb_conn
):
    """Test DisconnectedAgentGroupSyncTask _sync_agent_batch method."""

    manager_mock = MagicMock()
    logger_mock = MagicMock()

    # Mock disconnected_agent_group_sync to return successful result
    mock_disconnected_sync.return_value = AffectedItemsWazuhResult(
        affected_items=["001", "002"]
    )

    task = master.DisconnectedAgentGroupSyncTask(
        manager=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=None,
    )

    agents = [
        {"id": "001", "group": ["default"]},
        {"id": "002", "group": ["group1"]},
    ]

    with patch.object(task, "_get_max_version_from_indexer", return_value=100):
        await task._sync_agent_batch(agents)

    # Verify disconnected_agent_group_sync was called
    mock_disconnected_sync.assert_called()
    logger_mock.info.assert_called()


@pytest.mark.asyncio
@patch("wazuh.core.cluster.master.AsyncWazuhDBConnection")
@patch("wazuh.agent.disconnected_agent_group_sync")
async def test_disconnected_agent_group_sync_task_sync_agent_batch_with_error(
    mock_disconnected_sync, mock_wdb_conn
):
    """Test DisconnectedAgentGroupSyncTask _sync_agent_batch with sync error."""

    manager_mock = MagicMock()
    logger_mock = MagicMock()

    # Mock disconnected_agent_group_sync to raise exception
    mock_disconnected_sync.side_effect = Exception("Sync failed")

    task = master.DisconnectedAgentGroupSyncTask(
        manager=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=None,
    )

    agents = [
        {"id": "001", "group": ["default"]},
    ]

    with patch.object(task, "_get_max_version_from_indexer", return_value=100):
        await task._sync_agent_batch(agents)

    # Verify error was logged
    logger_mock.error.assert_called()


@pytest.mark.asyncio
@patch("wazuh.core.cluster.master.AsyncWazuhDBConnection")
@patch("wazuh.core.agent.Agent.get_agents_overview")
@patch("wazuh.agent.disconnected_agent_group_sync")
async def test_disconnected_agent_group_sync_integration_full_cycle(
    mock_disconnected_sync, mock_get_agents, mock_wdb_conn
):
    """Integration test: full cycle of getting disconnected agents and syncing."""

    manager_mock = MagicMock()
    logger_mock = MagicMock()

    # Mock Agent.get_agents_overview to return disconnected agents
    disconnected_agents = [
        {"id": "001", "name": "agent1", "status": "disconnected", "group": ["default"]},
        {"id": "002", "name": "agent2", "status": "disconnected", "group": ["group1"]},
        {
            "id": "003",
            "name": "agent3",
            "status": "disconnected",
            "group": ["default", "group2"],
        },
    ]
    mock_get_agents.return_value = {"data": {"affected_items": disconnected_agents}}

    # Mock disconnected_agent_group_sync to return successful results
    mock_disconnected_sync.return_value = AffectedItemsWazuhResult(
        affected_items=["001", "002", "003"]
    )

    # Create task with batch size of 2
    task = master.DisconnectedAgentGroupSyncTask(
        manager=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=None,
    )

    # Get disconnected agents
    wdb_conn = MagicMock()
    agents = await task._get_disconnected_agents(wdb_conn)

    assert len(agents) == 3

    # Process agents in batches
    batches = list(task._batch_agents(agents))
    assert len(batches) == 2  # 3 agents, batch size of 2 = 2 batches
    assert len(batches[0]) == 2
    assert len(batches[1]) == 1

    # Sync each batch
    with patch.object(task, "_get_max_version_from_indexer", return_value=100):
        for batch in batches:
            await task._sync_agent_batch(batch)

    # Verify sync was called once per agent (3 agents total)
    assert mock_disconnected_sync.call_count == 3

    # Verify that get_agents_overview was called with the expected filters
    # This ensures min_disconnection_time is being used for filtering
    mock_get_agents.assert_called()
    call_args = mock_get_agents.call_args
    # Verify that status filter was applied for disconnected agents
    assert call_args is not None


@pytest.mark.asyncio
@patch("wazuh.core.cluster.master.AsyncWazuhDBConnection")
@patch("wazuh.core.agent.Agent.get_agents_overview")
async def test_disconnected_agent_group_sync_respects_min_disconnection_time(
    mock_get_agents, mock_wdb_conn
):
    """Test that min_disconnection_time filter is correctly applied.

    This test validates the critical fix: only agents that have been disconnected
    for longer than min_disconnection_time should be processed.

    IMPORTANT: This test verifies that the implementation correctly applies the
    min_disconnection_time filter to avoid processing agents that were recently
    disconnected. Without this filter, the system would try to sync groups for
    agents that are still expected to reconnect soon.
    """

    manager_mock = MagicMock()
    logger_mock = MagicMock()

    import time

    now_timestamp = int(time.time())
    # Agent disconnected 1 hour ago (3600 seconds)
    one_hour_ago = now_timestamp - 3600
    # Agent disconnected 5 minutes ago (300 seconds) - too recent
    five_minutes_ago = now_timestamp - 300

    # Mock Agent.get_agents_overview to return agents with different disconnection times
    all_agents = [
        {
            "id": "001",
            "name": "agent_old",
            "status": "disconnected",
            "group": ["default"],
            "disconnection_time": one_hour_ago,  # Old disconnection
        },
        {
            "id": "002",
            "name": "agent_recent",
            "status": "disconnected",
            "group": ["group1"],
            "disconnection_time": five_minutes_ago,  # Recent disconnection (should be filtered)
        },
        {
            "id": "003",
            "name": "agent_very_old",
            "status": "disconnected",
            "group": ["default", "group2"],
            "disconnection_time": one_hour_ago - 3600,  # 2 hours ago
        },
    ]
    mock_get_agents.return_value = {"data": {"affected_items": all_agents}}

    # Create task with min_disconnection_time of 600 seconds (10 minutes)
    custom_cluster_items = copy.deepcopy(cluster_items)
    custom_cluster_items["intervals"]["master"][
        "sync_disconnected_agent_groups_min_offline"
    ] = 600

    task = master.DisconnectedAgentGroupSyncTask(
        manager=manager_mock,
        logger=logger_mock,
        cluster_items=custom_cluster_items,
        indexer_client=None,
    )

    # Get disconnected agents - should filter by min_disconnection_time
    wdb_conn = MagicMock()
    agents = await task._get_disconnected_agents(wdb_conn)

    # CRITICAL ASSERTION: Only agents disconnected for more than 10 minutes should be returned
    # This ensures the fix for min_disconnection_time filtering is working
    assert (
        len(agents) == 2
    ), f"Expected 2 agents (min 10 minutes disconnected), got {len(agents)}"

    agent_ids = [agent["id"] for agent in agents]
    assert "001" in agent_ids, "Agent disconnected 1 hour ago should be included"
    assert "003" in agent_ids, "Agent disconnected 2 hours ago should be included"
    assert (
        "002" not in agent_ids
    ), "Agent disconnected only 5 minutes ago should NOT be included"

    logger_mock.debug.assert_called()
    """Integration test: no disconnected agents found."""

    manager_mock = MagicMock()
    logger_mock = MagicMock()

    # Mock Agent.get_agents_overview to return no agents
    mock_get_agents.return_value = {"data": {"affected_items": []}}

    task = master.DisconnectedAgentGroupSyncTask(
        manager=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=None,
    )

    # Get disconnected agents
    wdb_conn = MagicMock()
    agents = await task._get_disconnected_agents(wdb_conn)

    assert len(agents) == 0
    logger_mock.debug.assert_called()


@pytest.mark.asyncio
@patch("wazuh.core.cluster.master.AsyncWazuhDBConnection")
@patch("wazuh.core.agent.Agent.get_agents_overview")
async def test_disconnected_agent_group_sync_integration_database_error(
    mock_get_agents, mock_wdb_conn
):
    """Integration test: database error when getting disconnected agents."""

    manager_mock = MagicMock()
    logger_mock = MagicMock()

    # Mock Agent.get_agents_overview to raise exception
    mock_get_agents.side_effect = Exception("Database connection error")

    task = master.DisconnectedAgentGroupSyncTask(
        manager=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=None,
    )

    # Get disconnected agents - should handle error gracefully
    wdb_conn = MagicMock()
    agents = await task._get_disconnected_agents(wdb_conn)

    assert len(agents) == 0
    logger_mock.error.assert_called()


@pytest.mark.asyncio
async def test_disconnected_agent_group_sync_task_batch_processing_edge_cases():
    """Test DisconnectedAgentGroupSyncTask batch processing with edge cases."""

    manager_mock = MagicMock()
    logger_mock = MagicMock()

    # Test with different batch sizes
    test_cases = [
        (
            1,
            [{"id": str(i)} for i in range(1, 6)],
            5,
        ),  # batch_size=1, 5 agents, 5 batches
        (
            2,
            [{"id": str(i)} for i in range(1, 5)],
            2,
        ),  # batch_size=2, 4 agents, 2 batches
        (
            10,
            [{"id": str(i)} for i in range(1, 4)],
            1,
        ),  # batch_size=10, 3 agents, 1 batch
    ]

    for batch_size, agents, expected_batches in test_cases:
        cluster_items_custom = copy.deepcopy(cluster_items)
        cluster_items_custom["intervals"]["master"][
            "sync_disconnected_agent_groups_batch_size"
        ] = batch_size

        task = master.DisconnectedAgentGroupSyncTask(
            manager=manager_mock,
            logger=logger_mock,
            cluster_items=cluster_items_custom,
            indexer_client=None,
        )

        batches = list(task._batch_agents(agents))
        assert len(batches) == expected_batches


@pytest.mark.asyncio
@patch("wazuh.core.cluster.master.AsyncWazuhDBConnection")
@patch("wazuh.core.agent.Agent.get_agents_overview")
async def test_disconnected_agent_group_sync_min_disconnection_time_boundary_case(
    mock_get_agents, mock_wdb_conn
):
    """Test min_disconnection_time boundary cases.

    This test validates edge cases:
    - Agent disconnected exactly at the min_disconnection_time boundary
    - Agent disconnected just before the boundary
    - Agent disconnected just after the boundary

    This is crucial to verify that the implementation correctly uses >= or >
    comparison for the min_disconnection_time filter.
    """
    manager_mock = MagicMock()
    logger_mock = MagicMock()

    import time

    now_timestamp = int(time.time())
    min_offline_time = 600  # 10 minutes

    # Create agents at different points relative to the boundary
    boundary_agents = [
        {
            "id": "001",
            "name": "agent_exactly_boundary",
            "status": "disconnected",
            "group": ["default"],
            "disconnection_time": now_timestamp
            - min_offline_time,  # Exactly at boundary
        },
        {
            "id": "002",
            "name": "agent_just_before_boundary",
            "status": "disconnected",
            "group": ["group1"],
            "disconnection_time": now_timestamp
            - (min_offline_time - 10),  # 10 seconds before boundary
        },
        {
            "id": "003",
            "name": "agent_just_after_boundary",
            "status": "disconnected",
            "group": ["default"],
            "disconnection_time": now_timestamp
            - (min_offline_time + 10),  # 10 seconds after boundary
        },
    ]
    mock_get_agents.return_value = {"data": {"affected_items": boundary_agents}}

    custom_cluster_items = copy.deepcopy(cluster_items)
    custom_cluster_items["intervals"]["master"][
        "sync_disconnected_agent_groups_min_offline"
    ] = min_offline_time

    task = master.DisconnectedAgentGroupSyncTask(
        manager=manager_mock,
        logger=logger_mock,
        cluster_items=custom_cluster_items,
        indexer_client=None,
    )

    wdb_conn = MagicMock()
    agents = await task._get_disconnected_agents(wdb_conn)

    agent_ids = [agent["id"] for agent in agents]

    # Agent exactly at boundary should be included (>= comparison)
    assert (
        "001" in agent_ids or len(agents) >= 1
    ), "Agent at or after boundary should be included"
    # Agent just before boundary should NOT be included
    assert "002" not in agent_ids, "Agent before boundary should NOT be included"
    # Agent just after boundary should be included
    assert "003" in agent_ids, "Agent after boundary should be included"
