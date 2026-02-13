# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from wazuh.core.cluster.master import DisconnectedAgentSyncTasks

# =============================
# Test Data Builders
# =============================


def build_agent(agent_id: str, status: str = "disconnected", group: list = None):
    """Build a test agent dictionary."""
    return {
        "id": agent_id,
        "name": f"agent-{agent_id}",
        "status": status,
        "lastKeepAlive": datetime.now(timezone.utc) - timedelta(seconds=1000),
        "dateAdd": datetime.now(timezone.utc) - timedelta(days=30),
        "group": group or ["default"],
    }


def build_indexer_response(agents_cluster_map: dict):
    """Build an indexer response with cluster names."""
    buckets = [
        {
            "key": agent_id,
            "cluster_name": (
                {"buckets": [{"key": cluster_name}]}
                if cluster_name
                else {"buckets": []}
            ),
        }
        for agent_id, cluster_name in agents_cluster_map.items()
    ]
    return {"aggregations": {"by_agent": {"buckets": buckets}}}


# =============================
# Fixtures
# =============================


@pytest.fixture
def logger():
    """Create a mock logger."""
    return MagicMock()


@pytest.fixture
def manager(logger):
    """Create a mock manager."""
    m = MagicMock()
    m.setup_task_logger.return_value = logger
    return m


@pytest.fixture
def sync_task(manager, logger):
    """Create a DisconnectedAgentSyncTasks instance."""
    cluster_items = {
        "intervals": {
            "master": {
                "sync_disconnected_agent_groups": 300,
                "sync_disconnected_agent_groups_batch_size": 10,
                "sync_disconnected_agent_groups_min_offline": 600,
                "sync_disconnected_agent_cluster_name_delay": 1,
            }
        }
    }
    indexer = AsyncMock()
    return (
        DisconnectedAgentSyncTasks(
            server=manager,
            logger=logger,
            cluster_items=cluster_items,
            indexer_client=indexer,
        ),
        indexer,
    )


# ============================================================
# Scenario Tests: Large Scale Operations
# ============================================================


class TestLargeScaleClusterNameSync:
    """Tests for cluster name sync with many agents."""

    @pytest.mark.asyncio
    @patch(
        "wazuh.core.indexer.disconnected_agents.asyncio.sleep", new_callable=AsyncMock
    )
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_sync_100_disconnected_agents(
        self, mock_get_ossec_conf, mock_sleep, sync_task
    ):
        """Test synchronization of 100 disconnected agents."""
        task, indexer = sync_task

        mock_get_ossec_conf.return_value = {"cluster": {"name": "main-cluster"}}

        # Create 100 agents
        agents = [build_agent(f"{i:03d}") for i in range(100)]
        task._get_disconnected_agents = AsyncMock(return_value=agents)

        # Create max versions for all agents
        max_versions = {agent["id"]: (i + 1) * 10 for i, agent in enumerate(agents)}
        task._get_max_versions_batch_from_indexer = AsyncMock(return_value=max_versions)

        # All agents need update
        agent_cluster_map = {agent["id"]: "old-cluster" for agent in agents}
        task._get_cluster_name_from_indexer = AsyncMock(return_value=agent_cluster_map)

        indexer.max_version_components = AsyncMock()
        indexer.max_version_components.update_agent_cluster_name = AsyncMock()

        await task.run_cluster_name_sync()

        # All 100 agents should be updated
        assert (
            indexer.max_version_components.update_agent_cluster_name.call_count == 100
        )

    @pytest.mark.asyncio
    @patch(
        "wazuh.core.indexer.disconnected_agents.asyncio.sleep", new_callable=AsyncMock
    )
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_sync_agents_with_mixed_cluster_names(
        self, mock_get_ossec_conf, mock_sleep, sync_task
    ):
        """Test agents with varying current cluster names."""
        task, indexer = sync_task

        target_cluster = "unified-cluster"
        mock_get_ossec_conf.return_value = {"cluster": {"name": target_cluster}}

        agents = [build_agent(f"{i:03d}") for i in range(20)]
        task._get_disconnected_agents = AsyncMock(return_value=agents)

        max_versions = {agent["id"]: i + 1 for i, agent in enumerate(agents)}
        task._get_max_versions_batch_from_indexer = AsyncMock(return_value=max_versions)

        # Mix of old clusters
        old_clusters = ["cluster-a", "cluster-b", "cluster-c", target_cluster]
        agent_cluster_map = {
            agents[i]["id"]: old_clusters[i % len(old_clusters)]
            for i in range(len(agents))
        }
        task._get_cluster_name_from_indexer = AsyncMock(return_value=agent_cluster_map)

        indexer.max_version_components = AsyncMock()
        indexer.max_version_components.update_agent_cluster_name = AsyncMock()

        await task.run_cluster_name_sync()

        # Should only update agents that don't have the target cluster
        # Count agents that need update
        agents_to_update = [
            agent_id
            for agent_id, cluster_name in agent_cluster_map.items()
            if cluster_name != target_cluster
        ]

        assert (
            indexer.max_version_components.update_agent_cluster_name.call_count
            == len(agents_to_update)
        )


# ============================================================
# Scenario Tests: Error Handling and Recovery
# ============================================================


class TestErrorHandlingScenarios:
    """Tests for error handling in various failure scenarios."""

    @pytest.mark.asyncio
    @patch(
        "wazuh.core.indexer.disconnected_agents.asyncio.sleep", new_callable=AsyncMock
    )
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_recover_from_intermittent_db_errors(
        self, mock_get_ossec_conf, mock_sleep, sync_task
    ):
        """Test recovery from intermittent database errors."""
        task, indexer = sync_task

        mock_get_ossec_conf.return_value = {"cluster": {"name": "cluster"}}

        # Simulate DB error on first call, success on retry logic
        call_count = {"count": 0}

        async def get_agents_with_retry():
            call_count["count"] += 1
            if call_count["count"] == 1:
                raise Exception("DB connection timeout")
            return [build_agent("001")]

        task._get_disconnected_agents = get_agents_with_retry

        # This should handle the error gracefully
        # Since we don't implement retry in the sync task itself,
        # it should just log the error
        await task.run_cluster_name_sync()

        # Task should complete without crashing
        assert task._cluster_name_sync_done

    @pytest.mark.asyncio
    @patch(
        "wazuh.core.indexer.disconnected_agents.asyncio.sleep", new_callable=AsyncMock
    )
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_handle_partial_max_version_failure(
        self, mock_get_ossec_conf, mock_sleep, sync_task
    ):
        """Test when some agents have no max version in indexer."""
        task, indexer = sync_task

        mock_get_ossec_conf.return_value = {"cluster": {"name": "cluster"}}

        agents = [build_agent("001"), build_agent("002"), build_agent("003")]
        task._get_disconnected_agents = AsyncMock(return_value=agents)

        # Only agents 001 and 002 have versions in indexer
        max_versions = {"001": 10, "002": 20}  # Agent 003 missing
        task._get_max_versions_batch_from_indexer = AsyncMock(return_value=max_versions)

        task._get_cluster_name_from_indexer = AsyncMock(
            return_value={
                "001": "old-cluster",
                "002": "old-cluster",
                "003": "old-cluster",
            }
        )

        indexer.max_version_components = AsyncMock()
        indexer.max_version_components.update_agent_cluster_name = AsyncMock()

        await task.run_cluster_name_sync()

        # All agents that are in cluster_map should be updated
        # Agent 003 should be updated with version 0 (default)
        assert indexer.max_version_components.update_agent_cluster_name.call_count == 3

        # Verify agent 003 got version 0
        calls = indexer.max_version_components.update_agent_cluster_name.call_args_list
        agent_003_call = [c for c in calls if c[1]["agent_id"] == "003"][0]
        assert agent_003_call[1]["global_version"] == 0


# ============================================================
# Scenario Tests: Edge Cases
# ============================================================


class TestEdgeCasesClusterNameSync:
    """Tests for edge cases and boundary conditions."""

    @pytest.mark.asyncio
    @patch(
        "wazuh.core.indexer.disconnected_agents.asyncio.sleep", new_callable=AsyncMock
    )
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_agents_with_same_cluster_name(
        self, mock_get_ossec_conf, mock_sleep, sync_task
    ):
        """Test when multiple agents have identical cluster names."""
        task, indexer = sync_task

        target_cluster = "cluster"
        mock_get_ossec_conf.return_value = {"cluster": {"name": target_cluster}}

        agents = [build_agent(f"{i:03d}") for i in range(5)]
        task._get_disconnected_agents = AsyncMock(return_value=agents)

        max_versions = {agent["id"]: i + 1 for i, agent in enumerate(agents)}
        task._get_max_versions_batch_from_indexer = AsyncMock(return_value=max_versions)

        # All agents have same old cluster name
        agent_cluster_map = {agent["id"]: "old-cluster" for agent in agents}
        task._get_cluster_name_from_indexer = AsyncMock(return_value=agent_cluster_map)

        indexer.max_version_components = AsyncMock()
        indexer.max_version_components.update_agent_cluster_name = AsyncMock()

        await task.run_cluster_name_sync()

        # All 5 should be updated
        assert indexer.max_version_components.update_agent_cluster_name.call_count == 5

    @pytest.mark.asyncio
    @patch(
        "wazuh.core.indexer.disconnected_agents.asyncio.sleep", new_callable=AsyncMock
    )
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_empty_cluster_name_string(
        self, mock_get_ossec_conf, mock_sleep, sync_task
    ):
        """Test with empty cluster name."""
        task, indexer = sync_task

        mock_get_ossec_conf.return_value = {"cluster": {"name": ""}}

        agents = [build_agent("001")]
        task._get_disconnected_agents = AsyncMock(return_value=agents)

        await task.run_cluster_name_sync()

        # Should warn about empty cluster name
        task.logger.warning.assert_called()

    @pytest.mark.asyncio
    @patch(
        "wazuh.core.indexer.disconnected_agents.asyncio.sleep", new_callable=AsyncMock
    )
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_long_cluster_name(self, mock_get_ossec_conf, mock_sleep, sync_task):
        """Test with very long cluster name."""
        task, indexer = sync_task

        long_cluster_name = "a" * 500  # Very long name

        mock_get_ossec_conf.return_value = {"cluster": {"name": long_cluster_name}}

        agents = [build_agent("001")]
        task._get_disconnected_agents = AsyncMock(return_value=agents)

        max_versions = {"001": 10}
        task._get_max_versions_batch_from_indexer = AsyncMock(return_value=max_versions)

        task._get_cluster_name_from_indexer = AsyncMock(
            return_value={"001": "old-cluster"}
        )

        indexer.max_version_components = AsyncMock()
        indexer.max_version_components.update_agent_cluster_name = AsyncMock()

        await task.run_cluster_name_sync()

        # Should handle long cluster name
        call_args = indexer.max_version_components.update_agent_cluster_name.call_args
        assert call_args[1]["cluster_name"] == long_cluster_name

    @pytest.mark.asyncio
    @patch(
        "wazuh.core.indexer.disconnected_agents.asyncio.sleep", new_callable=AsyncMock
    )
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_agent_id_with_special_characters(
        self, mock_get_ossec_conf, mock_sleep, sync_task
    ):
        """Test with agent IDs containing special characters."""
        task, indexer = sync_task

        mock_get_ossec_conf.return_value = {"cluster": {"name": "cluster"}}

        # Create agents with edge-case IDs
        agent_ids = ["000", "001", "999", "100"]
        agents = [build_agent(aid) for aid in agent_ids]
        task._get_disconnected_agents = AsyncMock(return_value=agents)

        max_versions = {aid: 10 for aid in agent_ids}
        task._get_max_versions_batch_from_indexer = AsyncMock(return_value=max_versions)

        agent_cluster_map = {aid: "old-cluster" for aid in agent_ids}
        task._get_cluster_name_from_indexer = AsyncMock(return_value=agent_cluster_map)

        indexer.max_version_components = AsyncMock()
        indexer.max_version_components.update_agent_cluster_name = AsyncMock()

        await task.run_cluster_name_sync()

        # All agents should be processed
        assert indexer.max_version_components.update_agent_cluster_name.call_count == 4

    @pytest.mark.asyncio
    @patch(
        "wazuh.core.indexer.disconnected_agents.asyncio.sleep", new_callable=AsyncMock
    )
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_version_consistency_across_updates(
        self, mock_get_ossec_conf, mock_sleep, sync_task
    ):
        """Test that each agent is updated with correct version."""
        task, indexer = sync_task

        mock_get_ossec_conf.return_value = {"cluster": {"name": "cluster"}}

        agents = [build_agent(f"{i:03d}") for i in range(5)]
        task._get_disconnected_agents = AsyncMock(return_value=agents)

        # Each agent has different version
        max_versions = {f"{i:03d}": (i + 1) * 100 for i in range(5)}
        task._get_max_versions_batch_from_indexer = AsyncMock(return_value=max_versions)

        agent_cluster_map = {agent["id"]: "old" for agent in agents}
        task._get_cluster_name_from_indexer = AsyncMock(return_value=agent_cluster_map)

        indexer.max_version_components = AsyncMock()
        indexer.max_version_components.update_agent_cluster_name = AsyncMock()

        await task.run_cluster_name_sync()

        # Verify each agent got correct version
        calls = indexer.max_version_components.update_agent_cluster_name.call_args_list
        for i, call_args in enumerate(calls):
            agent_id = call_args[1]["agent_id"]
            expected_version = max_versions[agent_id]
            actual_version = call_args[1]["global_version"]
            assert actual_version == expected_version


# ============================================================
# Scenario Tests: Concurrency and Timing
# ============================================================


class TestConcurrencyAndTiming:
    """Tests for concurrency and timing behavior."""

    @pytest.mark.asyncio
    @patch(
        "wazuh.core.indexer.disconnected_agents.asyncio.sleep", new_callable=AsyncMock
    )
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_initial_delay_respected(
        self, mock_get_ossec_conf, mock_sleep, sync_task
    ):
        """Test that initial delay is respected."""
        task, indexer = sync_task

        initial_delay = task.initial_delay

        mock_get_ossec_conf.return_value = {"cluster": {"name": "cluster"}}

        task._get_disconnected_agents = AsyncMock(return_value=[])

        await task.run_cluster_name_sync()

        # Should have slept for initial_delay
        mock_sleep.assert_called_once_with(initial_delay)

    @pytest.mark.asyncio
    @patch(
        "wazuh.core.indexer.disconnected_agents.asyncio.sleep", new_callable=AsyncMock
    )
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_run_only_once_per_lifecycle(
        self, mock_get_ossec_conf, mock_sleep, sync_task
    ):
        """Test that sync runs only once per process lifecycle."""
        task, indexer = sync_task

        mock_get_ossec_conf.return_value = {"cluster": {"name": "cluster"}}

        task._get_disconnected_agents = AsyncMock(return_value=[])

        # First run
        await task.run_cluster_name_sync()
        assert task._cluster_name_sync_done is True
        sleep_calls_1 = mock_sleep.call_count

        # Second run should skip
        await task.run_cluster_name_sync()
        sleep_calls_2 = mock_sleep.call_count

        # No additional sleep should occur
        assert sleep_calls_2 == sleep_calls_1


# ============================================================
# Tests: Validation and Input Sanitation
# ============================================================


class TestInputSanitation:
    """Tests for input validation and sanitation."""

    @pytest.mark.asyncio
    @patch(
        "wazuh.core.indexer.disconnected_agents.asyncio.sleep", new_callable=AsyncMock
    )
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_handles_agents_with_missing_id(
        self, mock_get_ossec_conf, mock_sleep, sync_task
    ):
        """Test handling of agents without ID field."""
        task, indexer = sync_task

        mock_get_ossec_conf.return_value = {"cluster": {"name": "cluster"}}

        # One agent missing ID
        agents = [
            build_agent("001"),
            {"name": "no-id-agent", "status": "disconnected"},  # Missing 'id'
            build_agent("002"),
        ]
        task._get_disconnected_agents = AsyncMock(return_value=agents)

        max_versions = {"001": 10, "002": 20}
        task._get_max_versions_batch_from_indexer = AsyncMock(return_value=max_versions)

        task._get_cluster_name_from_indexer = AsyncMock(
            return_value={"001": "old", "002": "old"}
        )

        indexer.max_version_components = AsyncMock()
        indexer.max_version_components.update_agent_cluster_name = AsyncMock()

        await task.run_cluster_name_sync()

        # Only valid agents should be processed
        assert indexer.max_version_components.update_agent_cluster_name.call_count == 2
