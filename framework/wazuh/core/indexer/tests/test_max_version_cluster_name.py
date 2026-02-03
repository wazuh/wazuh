# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
Unit tests for MaxVersionIndex cluster name synchronization operations.

This module tests the low-level indexer operations for updating cluster names
on indexed documents for disconnected agents.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wazuh.core.indexer.max_version_components import MaxVersionIndex


# =============================
# Fixtures
# =============================


@pytest.fixture
def indexer_client():
    """Create a mock AsyncOpenSearch client."""
    return AsyncMock()


@pytest.fixture
def max_version_index(indexer_client):
    """Create a MaxVersionIndex instance."""
    return MaxVersionIndex(client=indexer_client)


# ============================================================
# Tests: update_agent_cluster_name
# ============================================================


class TestUpdateAgentClusterName:
    """Test suite for update_agent_cluster_name() method."""

    @pytest.mark.asyncio
    async def test_update_cluster_name_success(self, max_version_index, indexer_client):
        """Test successful cluster name update across all module indices."""
        indexer_client.update_by_query.return_value = {
            "took": 100,
            "timed_out": False,
            "total": 5,
            "updated": 5,
            "deleted": 0,
            "batches": 1,
            "version_conflicts": 0,
            "noops": 0,
            "retries": {"bulk": 0, "search": 0},
            "throttled_millis": 0,
            "requests_per_second": -1.0,
            "throttled_until_millis": 0,
            "failures": [],
        }

        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="production-cluster",
            global_version=42,
        )

        # Should iterate through all modules and indices
        expected_calls = sum(
            len(indices) for indices in max_version_index.MODULE_INDICES_MAP.values()
        )
        assert indexer_client.update_by_query.call_count == expected_calls

        # Verify refresh was set
        for call in indexer_client.update_by_query.call_args_list:
            assert call[1]["refresh"] is True
            assert call[1]["conflicts"] == "proceed"

    @pytest.mark.asyncio
    async def test_update_cluster_name_with_custom_version(self, max_version_index, indexer_client):
        """Test that global_version is correctly passed in params."""
        indexer_client.update_by_query.return_value = {"updated": 3}

        custom_version = 9999

        await max_version_index.update_agent_cluster_name(
            agent_id="002",
            cluster_name="staging-cluster",
            global_version=custom_version,
        )

        # Check first call's parameters
        call_args = indexer_client.update_by_query.call_args_list[0]
        script_params = call_args[1]["body"]["script"]["params"]

        assert script_params["globalVersion"] == custom_version

    @pytest.mark.asyncio
    async def test_update_cluster_name_script_structure(self, max_version_index, indexer_client):
        """Test that the update script has correct structure."""
        indexer_client.update_by_query.return_value = {"updated": 1}

        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="test-cluster",
            global_version=10,
        )

        # Extract the first call's script
        call_args = indexer_client.update_by_query.call_args_list[0]
        script = call_args[1]["body"]["script"]

        # Verify script structure
        assert script["lang"] == "painless"
        assert "source" in script
        assert "params" in script

        source = script["source"]

        # Verify script initializes wazuh structure
        assert "ctx._source.wazuh" in source
        assert "ctx._source.wazuh.cluster" in source

        # Verify script sets cluster name
        assert "ctx._source.wazuh.cluster.name" in source

        # Verify script handles state
        assert "ctx._source.state" in source
        assert "ctx._source.state.document_version" in source
        assert "ctx._source.state.modified_at" in source

        # Verify noop when cluster name matches
        assert "ctx.op = \"noop\"" in source

    @pytest.mark.asyncio
    async def test_update_cluster_name_query_structure(self, max_version_index, indexer_client):
        """Test that the update query correctly filters agents."""
        indexer_client.update_by_query.return_value = {"updated": 2}

        agent_id = "012"

        await max_version_index.update_agent_cluster_name(
            agent_id=agent_id,
            cluster_name="cluster",
            global_version=5,
        )

        call_args = indexer_client.update_by_query.call_args_list[0]
        query = call_args[1]["body"]["query"]

        # Verify query structure
        assert "bool" in query
        assert "must" in query["bool"]

        # Verify agent.id term filter
        must_clause = query["bool"]["must"]
        assert any(
            "agent.id" in str(clause) for clause in must_clause
        ), "Query should filter by agent.id"

    @pytest.mark.asyncio
    async def test_update_cluster_name_different_agents(self, max_version_index, indexer_client):
        """Test updates for different agents use correct identifiers."""
        indexer_client.update_by_query.return_value = {"updated": 1}

        agents = ["001", "050", "999"]

        for agent_id in agents:
            indexer_client.reset_mock()

            await max_version_index.update_agent_cluster_name(
                agent_id=agent_id,
                cluster_name="cluster",
                global_version=1,
            )

            # Verify agent_id appears in query
            call_args = indexer_client.update_by_query.call_args_list[0]
            query_str = str(call_args[1]["body"]["query"])
            assert agent_id in query_str

    @pytest.mark.asyncio
    async def test_update_cluster_name_partial_index_failure(self, max_version_index, indexer_client):
        """Test handling when some indices fail to update."""
        # Alternate between success and failure
        side_effects = [
            {"updated": 2},
            Exception("Connection timeout"),
            {"updated": 1},
            {"updated": 0},
            Exception("Index locked"),
        ]

        indexer_client.update_by_query.side_effect = side_effects

        result = await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=10,
        )

        # Result should contain errors for failed indices
        errors = {k: v for k, v in result.items() if "error" in str(v)}
        assert len(errors) >= 2, "Should have errors for failed indices"

    @pytest.mark.asyncio
    async def test_update_cluster_name_all_modules_processed(self, max_version_index, indexer_client):
        """Test that all modules are processed."""
        indexer_client.update_by_query.return_value = {"updated": 1}

        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=1,
        )

        # Collect all modules that were processed
        processed_modules = set()
        for call_args in indexer_client.update_by_query.call_args_list:
            index_name = call_args[1]["index"]
            # Determine module from index name
            for module, indices in max_version_index.MODULE_INDICES_MAP.items():
                if index_name in indices:
                    processed_modules.add(module)

        # Verify all modules were processed
        expected_modules = set(max_version_index.MODULE_INDICES_MAP.keys())
        assert processed_modules == expected_modules

    @pytest.mark.asyncio
    async def test_update_cluster_name_refresh_parameter(self, max_version_index, indexer_client):
        """Test that refresh parameter is correctly set."""
        indexer_client.update_by_query.return_value = {"updated": 1}

        # Test with refresh=True (default)
        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=1,
            refresh=True,
        )

        for call_args in indexer_client.update_by_query.call_args_list:
            assert call_args[1]["refresh"] is True

        indexer_client.reset_mock()

        # Test with refresh=False
        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=1,
            refresh=False,
        )

        for call_args in indexer_client.update_by_query.call_args_list:
            assert call_args[1]["refresh"] is False

    @pytest.mark.asyncio
    async def test_update_cluster_name_returns_results_dict(self, max_version_index, indexer_client):
        """Test that method returns a dict with results per index."""
        indexer_client.update_by_query.return_value = {"updated": 5, "total": 10}

        result = await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=1,
        )

        assert isinstance(result, dict)
        # Should have an entry for each index
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_update_cluster_name_logs_debug_info(self, max_version_index, indexer_client):
        """Test that debug logging occurs for successful updates."""
        indexer_client.update_by_query.return_value = {"updated": 3}

        with patch("wazuh.core.indexer.max_version_components.logging") as mock_logging:
            logger = MagicMock()
            mock_logging.getLogger.return_value = logger

            await max_version_index.update_agent_cluster_name(
                agent_id="001",
                cluster_name="cluster",
                global_version=1,
            )

    @pytest.mark.asyncio
    async def test_update_cluster_name_params_timestamp(self, max_version_index, indexer_client):
        """Test that timestamp parameter is included in script."""
        indexer_client.update_by_query.return_value = {"updated": 1}

        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=1,
        )

        call_args = indexer_client.update_by_query.call_args_list[0]
        params = call_args[1]["body"]["script"]["params"]

        assert "timestamp" in params
        # Timestamp should be ISO format
        assert "T" in params["timestamp"] or "-" in params["timestamp"]

    @pytest.mark.asyncio
    async def test_update_cluster_name_empty_agent_id(self, max_version_index, indexer_client):
        """Test update with empty agent ID."""
        indexer_client.update_by_query.return_value = {"updated": 0}

        result = await max_version_index.update_agent_cluster_name(
            agent_id="",
            cluster_name="cluster",
            global_version=1,
        )

        # Should still process but may not update anything
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_update_cluster_name_special_characters_in_cluster_name(
        self, max_version_index, indexer_client
    ):
        """Test update with special characters in cluster name."""
        indexer_client.update_by_query.return_value = {"updated": 1}

        special_names = [
            "cluster-with-dashes",
            "cluster_with_underscores",
            "cluster.with.dots",
            "cluster@special",
        ]

        for cluster_name in special_names:
            indexer_client.reset_mock()

            await max_version_index.update_agent_cluster_name(
                agent_id="001",
                cluster_name=cluster_name,
                global_version=1,
            )

            call_args = indexer_client.update_by_query.call_args_list[0]
            params = call_args[1]["body"]["script"]["params"]
            assert params["clusterName"] == cluster_name

    @pytest.mark.asyncio
    async def test_update_cluster_name_zero_version(self, max_version_index, indexer_client):
        """Test update with version=0."""
        indexer_client.update_by_query.return_value = {"updated": 1}

        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=0,
        )

        call_args = indexer_client.update_by_query.call_args_list[0]
        params = call_args[1]["body"]["script"]["params"]
        assert params["globalVersion"] == 0

    @pytest.mark.asyncio
    async def test_update_cluster_name_high_version(self, max_version_index, indexer_client):
        """Test update with very high version number."""
        indexer_client.update_by_query.return_value = {"updated": 1}

        high_version = 999999999

        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=high_version,
        )

        call_args = indexer_client.update_by_query.call_args_list[0]
        params = call_args[1]["body"]["script"]["params"]
        assert params["globalVersion"] == high_version


# ============================================================
# Tests: update_agent_groups (comparison tests)
# ============================================================


class TestUpdateAgentGroupsComparison:
    """Tests to ensure update_agent_groups and update_agent_cluster_name work similarly."""

    @pytest.mark.asyncio
    async def test_both_methods_use_same_module_indices(self, max_version_index, indexer_client):
        """Test that both update methods iterate the same indices."""
        indexer_client.update_by_query.return_value = {"updated": 1}

        # Call update_agent_groups
        await max_version_index.update_agent_groups(
            agent_id="001",
            groups=["default", "production"],
            global_version=5,
        )

        groups_calls = indexer_client.update_by_query.call_count
        indexer_client.reset_mock()

        # Call update_agent_cluster_name
        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=5,
        )

        cluster_calls = indexer_client.update_by_query.call_count

        # Should have same number of calls (one per index)
        assert groups_calls == cluster_calls

    @pytest.mark.asyncio
    async def test_both_methods_query_by_agent_id(self, max_version_index, indexer_client):
        """Test both methods filter by agent ID."""
        indexer_client.update_by_query.return_value = {"updated": 1}

        agent_id = "test-agent"

        # Test update_agent_groups
        await max_version_index.update_agent_groups(
            agent_id=agent_id,
            groups=["group1"],
            global_version=1,
        )

        groups_query = str(indexer_client.update_by_query.call_args_list[0][1]["body"]["query"])
        indexer_client.reset_mock()

        # Test update_agent_cluster_name
        await max_version_index.update_agent_cluster_name(
            agent_id=agent_id,
            cluster_name="cluster",
            global_version=1,
        )

        cluster_query = str(indexer_client.update_by_query.call_args_list[0][1]["body"]["query"])

        # Both should have the agent ID in the query
        assert agent_id in groups_query
        assert agent_id in cluster_query
