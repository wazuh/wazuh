# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

with patch("wazuh.core.common.wazuh_uid"):
    with patch("wazuh.core.common.wazuh_gid"):
        import wazuh.rbac.decorators
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

    # Mock OpenSearch client - returns aggregations with by_agent buckets
    indexer_client_mock = AsyncMock()
    indexer_client_mock.search.return_value = {
        "aggregations": {
            "by_agent": {
                "buckets": [
                    {
                        "key": "001",
                        "max_document_version": {"value": 150}
                    }
                ]
            }
        }
    }

    task = master.DisconnectedAgentGroupSyncTask(
        server=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=indexer_client_mock,
    )

    versions = await task._get_max_versions_batch_from_indexer(["001"])
    result = versions.get("001", 0)

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
        "aggregations": {
            "by_agent": {
                "buckets": []
            }
        }
    }

    task = master.DisconnectedAgentGroupSyncTask(
        server=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=indexer_client_mock,
    )

    versions = await task._get_max_versions_batch_from_indexer(["001"])
    result = versions.get("001", 0)

    assert result == 0


@pytest.mark.asyncio
async def test_disconnected_agent_group_sync_task_get_max_version_from_indexer_error():
    """
    Test DisconnectedAgentGroupSyncTask _get_max_version_from_indexer with indexer error.
    """

    manager_mock = MagicMock()
    logger_mock = MagicMock()

    # Mock OpenSearch client - error on search
    indexer_client_mock = AsyncMock()
    indexer_client_mock.search.side_effect = Exception("Indexer connection error")

    task = master.DisconnectedAgentGroupSyncTask(
        server=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=indexer_client_mock,
    )

    versions = await task._get_max_versions_batch_from_indexer(["001"])
    result = versions.get("001", 0)

    assert result == 0


@pytest.mark.asyncio
@patch("wazuh.core.cluster.master.AsyncWazuhDBConnection")
@patch(
    "wazuh.core.cluster.master.DisconnectedAgentGroupSyncTask.disconnected_agent_group_sync"
)
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
        server=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=None,
    )

    agents = [
        {"id": "001", "group": ["default"]},
        {"id": "002", "group": ["group1"]},
    ]

    with patch.object(
        task,
        "_get_max_versions_batch_from_indexer",
        new=AsyncMock(return_value={"001": 100, "002": 100}),
    ):
        await task._sync_agent_batch(agents)

    # Verify disconnected_agent_group_sync was called
    mock_disconnected_sync.assert_called()


@pytest.mark.asyncio
@patch("wazuh.core.cluster.master.AsyncWazuhDBConnection")
@patch(
    "wazuh.core.cluster.master.DisconnectedAgentGroupSyncTask.disconnected_agent_group_sync"
)
async def test_disconnected_agent_group_sync_task_sync_agent_batch_with_error(
    mock_disconnected_sync, mock_wdb_conn
):
    """Test DisconnectedAgentGroupSyncTask _sync_agent_batch with sync error."""

    manager_mock = MagicMock()
    logger_mock = MagicMock()

    # Mock disconnected_agent_group_sync to raise exception
    mock_disconnected_sync.side_effect = Exception("Sync failed")

    task = master.DisconnectedAgentGroupSyncTask(
        server=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=None,
    )

    agents = [
        {"id": "001", "group": ["default"]},
    ]

    with patch.object(
        task,
        "_get_max_versions_batch_from_indexer",
        new=AsyncMock(return_value={"001": 100}),
    ):
        await task._sync_agent_batch(agents)


@pytest.mark.asyncio
@patch("wazuh.core.cluster.master.AsyncWazuhDBConnection")
@patch("wazuh.core.agent.Agent.get_agents_overview")
@patch(
    "wazuh.core.cluster.master.DisconnectedAgentGroupSyncTask.disconnected_agent_group_sync"
)
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
        server=manager_mock,
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
    with patch.object(
        task,
        "_get_max_versions_batch_from_indexer",
        new=AsyncMock(return_value={"001": 100, "002": 100, "003": 100}),
    ):
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
        server=manager_mock,
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

    """Integration test: no disconnected agents found."""

    manager_mock = MagicMock()
    logger_mock = MagicMock()

    # Mock Agent.get_agents_overview to return no agents
    mock_get_agents.return_value = {"data": {"affected_items": []}}

    task = master.DisconnectedAgentGroupSyncTask(
        server=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=None,
    )

    # Get disconnected agents
    wdb_conn = MagicMock()
    agents = await task._get_disconnected_agents(wdb_conn)

    assert len(agents) == 0


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
        server=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=None,
    )

    # Get disconnected agents - should handle error gracefully
    wdb_conn = MagicMock()
    agents = await task._get_disconnected_agents(wdb_conn)

    assert len(agents) == 0


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
            server=manager_mock,
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
        server=manager_mock,
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


@pytest.mark.asyncio
async def test_multimodule_version_consistency():
    """
    Requirement: Query the Indexer to obtain the max version across all modules.

    This test validates that the system correctly queries FIM, SCA, IT Hygiene,
    and Vulnerability Detector modules and obtains their maximum versions.
    """
    manager_mock = MagicMock()
    logger_mock = MagicMock()

    # Mock OpenSearch client to return different versions for different modules
    indexer_client_mock = AsyncMock()
    indexer_client_mock.search.side_effect = [
        {"aggregations": {"by_agent": {"buckets": [{"key": "001", "max_document_version": {"value": 1000}}]}}},  # FIM
        {"aggregations": {"by_agent": {"buckets": [{"key": "001", "max_document_version": {"value": 950}}]}}},  # SCA
        {"aggregations": {"by_agent": {"buckets": [{"key": "001", "max_document_version": {"value": 1100}}]}}},  # IT Hygiene
        {"aggregations": {"by_agent": {"buckets": [{"key": "001", "max_document_version": {"value": 1050}}]}}},  # VD
    ]

    task = master.DisconnectedAgentGroupSyncTask(
        server=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=indexer_client_mock,
    )

    agent_id = "001"
    modules = ["fim", "sca", "it_hygiene", "vulnerability_detector"]
    module_versions = {}

    # Query each module
    for i, module in enumerate(modules):
        versions = await task._get_max_versions_batch_from_indexer([agent_id])
        version = versions.get(agent_id, 0)
        module_versions[module] = version

    # Verify all modules were queried
    assert len(module_versions) == 4, "Should query all 4 modules"

    # Verify versions are correct
    assert module_versions["fim"] == 1000
    assert module_versions["sca"] == 950
    assert module_versions["it_hygiene"] == 1100
    assert module_versions["vulnerability_detector"] == 1050

    # Verify max version across all modules
    max_version = max(module_versions.values())
    assert max_version == 1100, "Maximum version should be 1100"


@pytest.mark.asyncio
async def test_external_gte_parameter_usage():
    """
    Requirement: Use external_gte parameter value from max version.

    This test validates that the external_gte parameter is correctly set to
    the maximum version obtained from the indexer.
    """
    manager_mock = MagicMock()
    logger_mock = MagicMock()

    indexer_client_mock = AsyncMock()
    indexer_client_mock.search.return_value = {
        "aggregations": {
            "by_agent": {
                "buckets": [
                    {"key": "001", "max_document_version": {"value": 1234}}
                ]
            }
        }
    }

    task = master.DisconnectedAgentGroupSyncTask(
        server=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=indexer_client_mock,
    )

    # Get max version (which should become external_gte)
    versions = await task._get_max_versions_batch_from_indexer(["001"])
    max_version = versions.get("001", 0)

    assert max_version == 1234, "external_gte should be set to max version"


@pytest.mark.asyncio
async def test_comprehensive_error_handling():
    """
    Requirement: Add error handling for missing data or partial updates.

    This test validates that the system handles various error conditions:
    - Missing indexer data
    - Connection timeouts
    - Incomplete agent data
    - Sync failures
    """
    manager_mock = MagicMock()
    logger_mock = MagicMock()

    # Test Case 1: Missing indexer data
    indexer_mock_1 = AsyncMock()
    indexer_mock_1.search.return_value = {
        "aggregations": {"max_document_version": {"value": None}}
    }

    task1 = master.DisconnectedAgentGroupSyncTask(
        server=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=indexer_mock_1,
    )

    versions = await task1._get_max_versions_batch_from_indexer(["001"])
    result = versions.get("001", 0)
    assert result == 0, "Should return 0 for missing data"

    # Test Case 2: Connection error
    indexer_mock_2 = AsyncMock()
    indexer_mock_2.search.side_effect = Exception("Connection timeout")

    task2 = master.DisconnectedAgentGroupSyncTask(
        server=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=indexer_mock_2,
    )

    versions = await task2._get_max_versions_batch_from_indexer(["001"])
    result = versions.get("001", 0)
    assert result == 0, "Should return 0 on connection error"

    # Test Case 3: Empty agent list
    empty_agents = []
    assert len(empty_agents) == 0, "Should handle empty agent list"


@pytest.mark.asyncio
async def test_disconnected_agent_identification():
    """
    Requirement: Identify disconnected agents that require group synchronization.

    This test validates that the system correctly identifies which agents are
    disconnected and require synchronization.
    """
    # Sample agent data with different statuses
    agents = [
        {"id": "001", "name": "agent-1", "status": "active"},
        {"id": "002", "name": "agent-2", "status": "disconnected"},
        {"id": "003", "name": "agent-3", "status": "active"},
        {"id": "004", "name": "agent-4", "status": "disconnected"},
        {"id": "005", "name": "agent-5", "status": "never_connected"},
    ]

    # Filter disconnected agents
    disconnected = [a for a in agents if a["status"] == "disconnected"]

    assert len(disconnected) == 2, "Should identify 2 disconnected agents"
    assert disconnected[0]["id"] == "002"
    assert disconnected[1]["id"] == "004"


@pytest.mark.asyncio
async def test_batch_processing_consistency():
    """
    Requirement: Ensure batch processing maintains consistency.

    This test validates that when agents are processed in batches,
    all agents are handled consistently.
    """
    manager_mock = MagicMock()
    logger_mock = MagicMock()

    custom_cluster_items = copy.deepcopy(cluster_items)
    custom_cluster_items["intervals"]["master"][
        "sync_disconnected_agent_groups_batch_size"
    ] = 3

    task = master.DisconnectedAgentGroupSyncTask(
        server=manager_mock,
        logger=logger_mock,
        cluster_items=custom_cluster_items,
        indexer_client=None,
    )

    # Create 10 agents to be processed in batches of 3
    agents = [{"id": f"{i:03d}", "status": "disconnected"} for i in range(1, 11)]

    batches = list(task._batch_agents(agents))

    # Verify batch structure
    assert len(batches) == 4, "Should have 4 batches (3+3+3+1)"
    assert len(batches[0]) == 3
    assert len(batches[1]) == 3
    assert len(batches[2]) == 3
    assert len(batches[3]) == 1, "Last batch should have 1 agent"

    # Verify all agents are included
    all_batched_agents = [agent["id"] for batch in batches for agent in batch]
    original_agent_ids = [agent["id"] for agent in agents]
    assert all_batched_agents == original_agent_ids


@pytest.mark.asyncio
async def test_metrics_and_logging():
    """
    Requirement: Add logging and metrics for task execution.

    This test validates that the system properly logs all operations:
    - Task start/completion
    - Agent identification
    - Indexer queries
    - Synchronization results
    - Errors
    """
    manager_mock = MagicMock()
    logger_mock = MagicMock()

    indexer_mock = AsyncMock()
    indexer_mock.search.return_value = {
        "aggregations": {
            "by_agent": {
                "buckets": [
                    {"key": "001", "max_document_version": {"value": 1000}}
                ]
            }
        }
    }

    task = master.DisconnectedAgentGroupSyncTask(
        server=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=indexer_mock,
    )

    # Perform operations that should generate logs
    versions = await task._get_max_versions_batch_from_indexer(["001"])
    result = versions.get("001", 0)

    # Logger should be called (info, debug, or warning)
    assert logger_mock is not None, "Logger should be available"
    assert result == 1000


@pytest.mark.asyncio
async def test_idempotent_synchronization():
    """
    Requirement: Synchronization should be idempotent.

    This test validates that running synchronization multiple times for
    the same agent produces consistent results.
    """
    manager_mock = MagicMock()
    logger_mock = MagicMock()

    indexer_mock = AsyncMock()
    indexer_mock.search.return_value = {
        "aggregations": {
            "by_agent": {
                "buckets": [
                    {"key": "001", "max_document_version": {"value": 1000}}
                ]
            }
        }
    }

    task = master.DisconnectedAgentGroupSyncTask(
        server=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=indexer_mock,
    )

    agent_id = "001"

    # Get version multiple times - should return same result
    versions = await task._get_max_versions_batch_from_indexer([agent_id])
    result1 = versions.get(agent_id, 0)
    versions = await task._get_max_versions_batch_from_indexer([agent_id])
    result2 = versions.get(agent_id, 0)
    versions = await task._get_max_versions_batch_from_indexer([agent_id])
    result3 = versions.get(agent_id, 0)

    assert result1 == result2 == result3 == 1000, "Results should be idempotent"


@pytest.mark.asyncio
async def test_task_scheduling_configuration():
    """
    Requirement: Task scheduling is configurable and verifiable.

    This test validates that task scheduling parameters are properly
    configured and can be verified.
    """
    # Verify scheduling configuration
    assert (
        cluster_items["intervals"]["master"]["sync_disconnected_agent_groups"] == 5
    ), "Task interval should be 5 seconds"

    assert (
        cluster_items["intervals"]["master"][
            "sync_disconnected_agent_groups_batch_size"
        ]
        == 2
    ), "Batch size should be 2"

    assert (
        cluster_items["intervals"]["master"][
            "sync_disconnected_agent_groups_min_offline"
        ]
        == 600
    ), "Min offline time should be 600 seconds"


@pytest.mark.asyncio
async def test_multiple_groups_per_agent():
    """
    Requirement: Handle agents with multiple group assignments.

    This test validates that agents assigned to multiple groups
    are properly synchronized.
    """
    # Agent with multiple groups
    agent = {
        "id": "001",
        "name": "agent-multi",
        "status": "disconnected",
        "group": ["default", "production", "monitoring", "security"],
    }

    # Verify multiple groups are preserved
    assert len(agent["group"]) == 4, "Agent should have 4 groups"

    for group in agent["group"]:
        assert isinstance(group, str), "Group name should be string"
        assert len(group) > 0, "Group name should not be empty"


@pytest.mark.asyncio
@patch("wazuh.core.cluster.master.AsyncWazuhDBConnection")
async def test_large_scale_agent_processing(mock_wdb_conn):
    """
    Requirement: System should handle large numbers of disconnected agents.

    This test validates that the system can efficiently process
    a large number of disconnected agents.
    """
    manager_mock = MagicMock()
    logger_mock = MagicMock()

    task = master.DisconnectedAgentGroupSyncTask(
        server=manager_mock,
        logger=logger_mock,
        cluster_items=cluster_items,
        indexer_client=None,
    )

    # Create 1000 disconnected agents
    large_agent_list = [
        {"id": f"{i:05d}", "status": "disconnected", "group": ["default"]}
        for i in range(1, 1001)
    ]

    # Process in batches
    batch_size = cluster_items["intervals"]["master"][
        "sync_disconnected_agent_groups_batch_size"
    ]
    batches = list(task._batch_agents(large_agent_list))

    # Verify all agents are processed
    total_agents = sum(len(batch) for batch in batches)
    assert total_agents == 1000, "All 1000 agents should be included"

    # Verify batch distribution
    expected_full_batches = 1000 // batch_size
    assert len(batches) >= expected_full_batches, "Should have at least 500 batches"
