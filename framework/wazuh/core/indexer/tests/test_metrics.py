# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
Unit tests for MetricsIndex bulk indexing operations.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wazuh.core.indexer.metrics import MetricsIndex


@pytest.fixture
def mock_indexer_client():
    """Create a mock AsyncOpenSearch client."""
    return AsyncMock()


@pytest.fixture
def metrics_index(mock_indexer_client):
    """Create MetricsIndex instance with mock client."""
    return MetricsIndex(client=mock_indexer_client)


class TestMetricsIndexInit:
    """Tests for MetricsIndex initialization."""

    def test_init_stores_client(self, mock_indexer_client):
        """Verify that __init__ stores the client reference."""
        index = MetricsIndex(client=mock_indexer_client)
        assert index._client is mock_indexer_client


class TestBulkIndex:
    """Tests for MetricsIndex.bulk_index method."""

    @pytest.mark.asyncio
    async def test_bulk_index_calls_async_bulk(self, metrics_index):
        """Verify that bulk_index delegates to async_bulk."""
        docs = [{"field": "value1"}, {"field": "value2"}]

        with patch("wazuh.core.indexer.metrics.async_bulk", new_callable=AsyncMock, return_value=(2, 0)) as mock_bulk:
            await metrics_index.bulk_index(
                index="wazuh-metrics-agents",
                docs=docs,
                bulk_size=100,
            )
            mock_bulk.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_bulk_index_action_shape(self, metrics_index):
        """Verify each action has _op_type create, _index, and _source."""
        docs = [{"agent_id": "001"}, {"agent_id": "002"}]

        with patch("wazuh.core.indexer.metrics.async_bulk", new_callable=AsyncMock, return_value=(2, 0)) as mock_bulk:
            await metrics_index.bulk_index(
                index="wazuh-metrics-agents",
                docs=docs,
                bulk_size=100,
            )

            _, call_args, call_kwargs = mock_bulk.mock_calls[0]
            actions = list(call_args[1])

            assert len(actions) == len(docs)
            for i, action in enumerate(actions):
                assert action["_op_type"] == "create"
                assert action["_index"] == "wazuh-metrics-agents"
                assert action["_source"] == docs[i]

    @pytest.mark.asyncio
    async def test_bulk_index_passes_chunk_size(self, metrics_index):
        """Verify chunk_size is mapped from bulk_size parameter."""
        docs = [{"x": 1}]

        with patch("wazuh.core.indexer.metrics.async_bulk", new_callable=AsyncMock, return_value=(1, 0)) as mock_bulk:
            await metrics_index.bulk_index(
                index="wazuh-metrics-comms",
                docs=docs,
                bulk_size=50,
            )

            call_kwargs = mock_bulk.mock_calls[0].kwargs
            assert call_kwargs["chunk_size"] == 50

    @pytest.mark.asyncio
    async def test_bulk_index_raise_on_error_false(self, metrics_index):
        """Verify raise_on_error=False so individual failures do not crash the task."""
        docs = [{"x": 1}]

        with patch("wazuh.core.indexer.metrics.async_bulk", new_callable=AsyncMock, return_value=(1, 0)) as mock_bulk:
            await metrics_index.bulk_index(
                index="wazuh-metrics-agents",
                docs=docs,
                bulk_size=100,
            )

            call_kwargs = mock_bulk.mock_calls[0].kwargs
            assert call_kwargs["raise_on_error"] is False

    @pytest.mark.asyncio
    async def test_bulk_index_passes_client(self, metrics_index, mock_indexer_client):
        """Verify the OpenSearch client is passed to async_bulk."""
        docs = [{"x": 1}]

        with patch("wazuh.core.indexer.metrics.async_bulk", new_callable=AsyncMock, return_value=(1, 0)) as mock_bulk:
            await metrics_index.bulk_index(
                index="wazuh-metrics-agents",
                docs=docs,
                bulk_size=100,
            )

            first_positional_arg = mock_bulk.mock_calls[0].args[0]
            assert first_positional_arg is mock_indexer_client

    @pytest.mark.asyncio
    async def test_bulk_index_empty_docs(self, metrics_index):
        """Verify bulk_index handles an empty document list without errors."""
        with patch("wazuh.core.indexer.metrics.async_bulk", new_callable=AsyncMock, return_value=(0, 0)) as mock_bulk:
            await metrics_index.bulk_index(
                index="wazuh-metrics-agents",
                docs=[],
                bulk_size=100,
            )

            _, call_args, _ = mock_bulk.mock_calls[0]
            actions = list(call_args[1])
            assert actions == []

    @pytest.mark.asyncio
    async def test_bulk_index_different_indices(self, metrics_index):
        """Verify _index is set correctly for different data stream names."""
        docs = [{"ts": "2026-03-11"}]

        for stream in ["wazuh-metrics-agents", "wazuh-metrics-comms"]:
            with patch("wazuh.core.indexer.metrics.async_bulk", new_callable=AsyncMock, return_value=(1, 0)) as mock_bulk:
                await metrics_index.bulk_index(
                    index=stream,
                    docs=docs,
                    bulk_size=100,
                )

                _, call_args, _ = mock_bulk.mock_calls[0]
                actions = list(call_args[1])
                assert actions[0]["_index"] == stream

    @pytest.mark.asyncio
    async def test_bulk_index_logs_warning_on_failures(self, metrics_index):
        """Verify a warning is logged when some documents fail to index."""
        docs = [{"x": i} for i in range(100)]

        with patch("wazuh.core.indexer.metrics.async_bulk", new_callable=AsyncMock, return_value=(95, 5)):
            metrics_index._logger = MagicMock()
            await metrics_index.bulk_index(
                index="wazuh-metrics-agents",
                docs=docs,
                bulk_size=100,
            )
            metrics_index._logger.warning.assert_called_once_with(
                "Metrics bulk index on '%s': %d indexed, %d failed",
                "wazuh-metrics-agents",
                95,
                5,
            )

    @pytest.mark.asyncio
    async def test_bulk_index_no_warning_on_success(self, metrics_index):
        """Verify no warning is logged when all documents are indexed successfully."""
        docs = [{"x": 1}]

        with patch("wazuh.core.indexer.metrics.async_bulk", new_callable=AsyncMock, return_value=(1, 0)):
            metrics_index._logger = MagicMock()
            await metrics_index.bulk_index(
                index="wazuh-metrics-agents",
                docs=docs,
                bulk_size=100,
            )
            metrics_index._logger.warning.assert_not_called()
