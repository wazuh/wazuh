# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

with patch("wazuh.core.common.wazuh_uid", "wazuh"), patch(
    "wazuh.core.common.wazuh_gid", "wazuh"
):
    from wazuh.core.cluster.master import DisconnectedAgentSyncTasks
    from wazuh.core.indexer.max_version_components import MaxVersionIndex


# =============================
# Cluster config fixtures
# =============================
CLUSTER_ITEMS_WITH_CLUSTER_NAME_SYNC = {
    "intervals": {
        "master": {
            "sync_disconnected_agent_groups": 300,
            "sync_disconnected_agent_groups_batch_size": 100,
            "sync_disconnected_agent_groups_min_offline": 600,
            "sync_disconnected_agent_cluster_name_delay": 5,
        }
    }
}


# =============================
# Fixtures
# =============================
@pytest.fixture
def logger():
    """Create a mock logger."""
    return MagicMock()


@pytest.fixture
def manager(logger):
    """Create a mock manager/server."""
    m = MagicMock()
    m.setup_task_logger.return_value = logger
    return m


@pytest.fixture
def task_with_indexer(manager, logger):
    """Create a DisconnectedAgentSyncTasks instance with mock indexer."""
    indexer = AsyncMock()
    task = DisconnectedAgentSyncTasks(
        server=manager,
        logger=logger,
        cluster_items=CLUSTER_ITEMS_WITH_CLUSTER_NAME_SYNC,
        indexer_client=indexer,
    )
    return task, indexer


@pytest.fixture
def max_version_index():
    """Create a MaxVersionIndex instance with mock client."""
    client = AsyncMock()
    return MaxVersionIndex(client=client), client


# ============================================================
# Tests: run_cluster_name_sync()
# ============================================================


class TestRunClusterNameSync:
    """Tests for the run_cluster_name_sync() method."""

    @pytest.mark.asyncio
    @patch("wazuh.core.cluster.master.asyncio.sleep", new_callable=AsyncMock)
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_cluster_name_sync_success(
        self, mock_get_ossec_conf, mock_sleep, task_with_indexer
    ):
        """Test successful cluster name synchronization for disconnected agents."""
        task, indexer = task_with_indexer

        mock_get_ossec_conf.return_value = {"cluster": {"name": "wazuh-cluster"}}

        task._get_disconnected_agents = AsyncMock(
            return_value=[
                {"id": "001", "status": "disconnected"},
                {"id": "002", "status": "disconnected"},
            ]
        )

        task._get_max_versions_batch_from_indexer = AsyncMock(
            return_value={"001": 10, "002": 20}
        )

        task._get_cluster_name_from_indexer = AsyncMock(
            return_value={"001": "old-cluster", "002": "old-cluster"}
        )

        indexer.max_version_components = MagicMock()
        indexer.max_version_components.update_agent_cluster_name = AsyncMock()

        await task.run_cluster_name_sync()

        mock_sleep.assert_called_once_with(5)
        task._get_disconnected_agents.assert_called_once()
        task._get_max_versions_batch_from_indexer.assert_called_once_with(
            ["001", "002"]
        )
        task._get_cluster_name_from_indexer.assert_called_once()
        assert indexer.max_version_components.update_agent_cluster_name.call_count == 2

    @pytest.mark.asyncio
    @patch("wazuh.core.cluster.master.asyncio.sleep", new_callable=AsyncMock)
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_cluster_name_sync_already_executed(
        self, mock_get_ossec_conf, mock_sleep, task_with_indexer
    ):
        """Test that cluster name sync is skipped if already executed."""
        task, indexer = task_with_indexer
        task._cluster_name_sync_done = True

        await task.run_cluster_name_sync()

        mock_sleep.assert_not_called()
        task.logger.debug.assert_any_call(
            "Cluster-name sync already executed; skipping"
        )

    @pytest.mark.asyncio
    @patch("wazuh.core.cluster.master.asyncio.sleep", new_callable=AsyncMock)
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_cluster_name_sync_no_disconnected_agents(
        self, mock_get_ossec_conf, mock_sleep, task_with_indexer
    ):
        """Test sync when no disconnected agents are found."""
        task, indexer = task_with_indexer

        mock_get_ossec_conf.return_value = {"cluster": {"name": "wazuh-cluster"}}
        task._get_disconnected_agents = AsyncMock(return_value=[])

        await task.run_cluster_name_sync()

        task.logger.info.assert_any_call(
            "No disconnected agents found for cluster-name sync"
        )
        assert task._cluster_name_sync_done

    @pytest.mark.asyncio
    @patch("wazuh.core.cluster.master.asyncio.sleep", new_callable=AsyncMock)
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_cluster_name_sync_missing_ossec_conf(
        self, mock_get_ossec_conf, mock_sleep, task_with_indexer
    ):
        """Test sync when cluster name is missing from ossec.conf."""
        task, indexer = task_with_indexer

        mock_get_ossec_conf.side_effect = Exception("Config not found")
        task._get_disconnected_agents = AsyncMock(
            return_value=[{"id": "001", "status": "disconnected"}]
        )

        await task.run_cluster_name_sync()

        task.logger.error.assert_called()
        assert task._cluster_name_sync_done

    @pytest.mark.asyncio
    @patch("wazuh.core.cluster.master.asyncio.sleep", new_callable=AsyncMock)
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_cluster_name_sync_empty_cluster_name(
        self, mock_get_ossec_conf, mock_sleep, task_with_indexer
    ):
        """Test sync when cluster name is empty in ossec.conf."""
        task, indexer = task_with_indexer

        mock_get_ossec_conf.return_value = {}
        task._get_disconnected_agents = AsyncMock(
            return_value=[{"id": "001", "status": "disconnected"}]
        )

        await task.run_cluster_name_sync()

        task.logger.warning.assert_called_with(
            "Cluster name not found in ossec.conf; aborting sync"
        )
        assert task._cluster_name_sync_done

    @pytest.mark.asyncio
    @patch("wazuh.core.cluster.master.asyncio.sleep", new_callable=AsyncMock)
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_cluster_name_sync_no_agents_need_update(
        self, mock_get_ossec_conf, mock_sleep, task_with_indexer
    ):
        """Test sync when all agents already have correct cluster name."""
        task, indexer = task_with_indexer

        mock_get_ossec_conf.return_value = {"cluster": {"name": "wazuh-cluster"}}

        task._get_disconnected_agents = AsyncMock(
            return_value=[
                {"id": "001", "status": "disconnected"},
            ]
        )

        task._get_max_versions_batch_from_indexer = AsyncMock(return_value={"001": 10})

        task._get_cluster_name_from_indexer = AsyncMock(
            return_value={"001": "wazuh-cluster"}
        )

        indexer.max_version_components = MagicMock()
        indexer.max_version_components.update_agent_cluster_name = AsyncMock()

        await task.run_cluster_name_sync()

        task.logger.info.assert_any_call(
            "All disconnected agents already have correct cluster name"
        )
        indexer.max_version_components.update_agent_cluster_name.assert_not_called()

    @pytest.mark.asyncio
    @patch("wazuh.core.cluster.master.asyncio.sleep", new_callable=AsyncMock)
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_cluster_name_sync_partial_update_failure(
        self, mock_get_ossec_conf, mock_sleep, task_with_indexer
    ):
        """Test sync continues even if some agents fail to update."""
        task, indexer = task_with_indexer

        mock_get_ossec_conf.return_value = {"cluster": {"name": "wazuh-cluster"}}

        task._get_disconnected_agents = AsyncMock(
            return_value=[
                {"id": "001", "status": "disconnected"},
                {"id": "002", "status": "disconnected"},
            ]
        )

        task._get_max_versions_batch_from_indexer = AsyncMock(
            return_value={"001": 10, "002": 20}
        )

        task._get_cluster_name_from_indexer = AsyncMock(
            return_value={"001": "old-cluster", "002": "old-cluster"}
        )

        indexer.max_version_components = MagicMock()
        update_side_effects = [None, Exception("Update failed")]
        indexer.max_version_components.update_agent_cluster_name = AsyncMock(
            side_effect=update_side_effects
        )

        await task.run_cluster_name_sync()

        task.logger.error.assert_called()
        assert indexer.max_version_components.update_agent_cluster_name.call_count == 2

    @pytest.mark.asyncio
    @patch("wazuh.core.cluster.master.asyncio.sleep", new_callable=AsyncMock)
    @patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
    async def test_cluster_name_sync_final_flag_set(
        self, mock_get_ossec_conf, mock_sleep, task_with_indexer
    ):
        """Test that _cluster_name_sync_done flag is always set at the end."""
        task, indexer = task_with_indexer

        mock_get_ossec_conf.side_effect = Exception("Error")
        task._get_disconnected_agents = AsyncMock(side_effect=Exception("DB error"))

        await task.run_cluster_name_sync()

        assert task._cluster_name_sync_done
