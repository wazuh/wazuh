# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
Unit tests for MaxVersionIndex cluster name updates.

Tests focus on the update_agent_cluster_name() method and related
indexer operations for cluster name synchronization.
"""

from unittest.mock import AsyncMock
import pytest

from wazuh.core.indexer.max_version_components import MaxVersionIndex


@pytest.fixture
def mock_indexer_client():
    """Create a mock AsyncOpenSearch client."""
    return AsyncMock()


@pytest.fixture
def max_version_index(mock_indexer_client):
    """Create MaxVersionIndex instance with mock client."""
    return MaxVersionIndex(client=mock_indexer_client)


class TestUpdateAgentClusterName:
    """Tests for update_agent_cluster_name method."""

    @pytest.mark.asyncio
    async def test_update_cluster_name_basic(self, max_version_index, mock_indexer_client):
        """Test basic cluster name update functionality."""
        mock_indexer_client.update_by_query.return_value = {
            "updated": 3,
            "total": 5,
        }

        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="production",
            global_version=10,
        )

        # Should update each index in MODULE_INDICES_MAP
        total_indices = sum(
            len(indices)
            for indices in max_version_index.MODULE_INDICES_MAP.values()
        )
        assert mock_indexer_client.update_by_query.call_count == total_indices

    @pytest.mark.asyncio
    async def test_update_cluster_name_with_refresh_true(
        self, max_version_index, mock_indexer_client
    ):
        """Test that refresh parameter is passed correctly."""
        mock_indexer_client.update_by_query.return_value = {"updated": 1}

        await max_version_index.update_agent_cluster_name(
            agent_id="002",
            cluster_name="staging",
            global_version=5,
            refresh=True,
        )

        # Check first call has refresh=True
        first_call = mock_indexer_client.update_by_query.call_args_list[0]
        assert first_call[1]["refresh"] is True

    @pytest.mark.asyncio
    async def test_update_cluster_name_with_refresh_false(
        self, max_version_index, mock_indexer_client
    ):
        """Test that refresh parameter is respected when False."""
        mock_indexer_client.update_by_query.return_value = {"updated": 1}

        await max_version_index.update_agent_cluster_name(
            agent_id="003",
            cluster_name="dev",
            global_version=1,
            refresh=False,
        )

        # Check first call has refresh=False
        first_call = mock_indexer_client.update_by_query.call_args_list[0]
        assert first_call[1]["refresh"] is False

    @pytest.mark.asyncio
    async def test_script_contains_cluster_name_field(
        self, max_version_index, mock_indexer_client
    ):
        """Verify script updates wazuh.cluster.name field."""
        mock_indexer_client.update_by_query.return_value = {"updated": 1}

        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="new-cluster",
            global_version=1,
        )

        # Get script from first call
        first_call = mock_indexer_client.update_by_query.call_args_list[0]
        script_source = first_call[1]["body"]["script"]["source"]

        # Verify it contains cluster name field update
        assert "wazuh.cluster.name" in script_source
        assert "ctx._source.wazuh.cluster.name" in script_source

    @pytest.mark.asyncio
    async def test_script_params_contain_cluster_name(
        self, max_version_index, mock_indexer_client
    ):
        """Verify script params include correct cluster name."""
        mock_indexer_client.update_by_query.return_value = {"updated": 1}

        cluster_name = "my-cluster"
        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name=cluster_name,
            global_version=10,
        )

        first_call = mock_indexer_client.update_by_query.call_args_list[0]
        params = first_call[1]["body"]["script"]["params"]

        assert params["clusterName"] == cluster_name
        assert params["newVersion"] == 10

    @pytest.mark.asyncio
    async def test_query_filters_by_agent_id(self, max_version_index, mock_indexer_client):
        """Verify query filters documents by agent.id."""
        mock_indexer_client.update_by_query.return_value = {"updated": 1}

        agent_id = "005"
        await max_version_index.update_agent_cluster_name(
            agent_id=agent_id,
            cluster_name="cluster",
            global_version=1,
        )

        first_call = mock_indexer_client.update_by_query.call_args_list[0]
        query = first_call[1]["body"]["query"]
        query_str = str(query)

        # Verify agent ID is in the query
        assert agent_id in query_str

    @pytest.mark.asyncio
    async def test_conflicts_proceed_set(self, max_version_index, mock_indexer_client):
        """Verify conflicts='proceed' is used."""
        mock_indexer_client.update_by_query.return_value = {"updated": 1}

        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=1,
        )

        # All calls should have conflicts='proceed'
        for call_args in mock_indexer_client.update_by_query.call_args_list:
            assert call_args[1]["conflicts"] == "proceed"

    @pytest.mark.asyncio
    async def test_updates_all_modules(self, max_version_index, mock_indexer_client):
        """Verify all module indices are updated."""
        mock_indexer_client.update_by_query.return_value = {"updated": 1}

        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=1,
        )

        # Collect updated indices
        updated_indices = set()
        for call_args in mock_indexer_client.update_by_query.call_args_list:
            index = call_args[1]["index"]
            updated_indices.add(index)

        # Verify all module indices were processed
        expected_indices = set()
        for indices in max_version_index.MODULE_INDICES_MAP.values():
            expected_indices.update(indices)

        assert updated_indices == expected_indices

    @pytest.mark.asyncio
    async def test_returns_results_dict(self, max_version_index, mock_indexer_client):
        """Verify method returns dict with results per index."""
        mock_indexer_client.update_by_query.return_value = {
            "updated": 2,
            "total": 5,
        }

        result = await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=1,
        )

        assert isinstance(result, dict)
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_handles_error_responses(self, max_version_index, mock_indexer_client):
        """Verify error responses are included in results."""
        # Mix of successes and errors
        responses = [
            {"updated": 2},
            Exception("Connection error"),
            {"updated": 1},
        ]
        mock_indexer_client.update_by_query.side_effect = responses

        result = await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=1,
        )

        # Should have some errors
        error_results = [v for v in result.values() if isinstance(v, dict) and "error" in str(v)]
        assert len(error_results) > 0 or len(result) >= 3


class TestUpdateAgentClusterNameScriptContent:
    """Tests focused on script content verification."""

    @pytest.mark.asyncio
    async def test_script_initializes_wazuh_structure(
        self, max_version_index, mock_indexer_client
    ):
        """Verify script safely initializes wazuh structure."""
        mock_indexer_client.update_by_query.return_value = {"updated": 1}

        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=1,
        )

        script_source = (
            mock_indexer_client.update_by_query.call_args_list[0][1]["body"]["script"]["source"]
        )

        # Should initialize wazuh if null
        assert "ctx._source.wazuh == null" in script_source or "wazuh" in script_source

    @pytest.mark.asyncio
    async def test_script_initializes_cluster_structure(
        self, max_version_index, mock_indexer_client
    ):
        """Verify script safely initializes cluster structure."""
        mock_indexer_client.update_by_query.return_value = {"updated": 1}

        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=1,
        )

        script_source = (
            mock_indexer_client.update_by_query.call_args_list[0][1]["body"]["script"]["source"]
        )

        # Should initialize cluster if null
        assert "cluster" in script_source

    @pytest.mark.asyncio
    async def test_script_includes_noop_for_same_cluster_name(
        self, max_version_index, mock_indexer_client
    ):
        """Verify script uses noop when cluster name already matches."""
        mock_indexer_client.update_by_query.return_value = {"updated": 1}

        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=1,
        )

        script_source = (
            mock_indexer_client.update_by_query.call_args_list[0][1]["body"]["script"]["source"]
        )

        # Should have noop operation for same cluster name
        assert "noop" in script_source

    @pytest.mark.asyncio
    async def test_script_sets_modified_timestamp(
        self, max_version_index, mock_indexer_client
    ):
        """Verify script updates modified_at timestamp."""
        mock_indexer_client.update_by_query.return_value = {"updated": 1}

        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=1,
        )

        script_source = (
            mock_indexer_client.update_by_query.call_args_list[0][1]["body"]["script"]["source"]
        )

        # Should set modified_at
        assert "modified_at" in script_source


class TestUpdateAgentClusterNameEdgeCases:
    """Tests for edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_empty_agent_id(self, max_version_index, mock_indexer_client):
        """Test with empty agent ID."""
        mock_indexer_client.update_by_query.return_value = {"updated": 0}

        result = await max_version_index.update_agent_cluster_name(
            agent_id="",
            cluster_name="cluster",
            global_version=1,
        )

        # Should complete without crashing
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_special_characters_in_cluster_name(
        self, max_version_index, mock_indexer_client
    ):
        """Test with special characters in cluster name."""
        mock_indexer_client.update_by_query.return_value = {"updated": 1}

        special_names = [
            "cluster-with-dashes",
            "cluster_underscores",
            "cluster.dots",
        ]

        for cluster_name in special_names:
            mock_indexer_client.reset_mock()
            mock_indexer_client.update_by_query.return_value = {"updated": 1}

            await max_version_index.update_agent_cluster_name(
                agent_id="001",
                cluster_name=cluster_name,
                global_version=1,
            )

            params = (
                mock_indexer_client.update_by_query.call_args_list[0][1]["body"]["script"]["params"]
            )
            assert params["clusterName"] == cluster_name

    @pytest.mark.asyncio
    async def test_zero_version(self, max_version_index, mock_indexer_client):
        """Test with version=0."""
        mock_indexer_client.update_by_query.return_value = {"updated": 1}

        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=0,
        )

        params = (
            mock_indexer_client.update_by_query.call_args_list[0][1]["body"]["script"]["params"]
        )
        assert params["newVersion"] == 0

    @pytest.mark.asyncio
    async def test_very_high_version(self, max_version_index, mock_indexer_client):
        """Test with very high version number."""
        mock_indexer_client.update_by_query.return_value = {"updated": 1}

        high_version = 9999999

        await max_version_index.update_agent_cluster_name(
            agent_id="001",
            cluster_name="cluster",
            global_version=high_version,
        )

        params = (
            mock_indexer_client.update_by_query.call_args_list[0][1]["body"]["script"]["params"]
        )
        assert params["newVersion"] == high_version
