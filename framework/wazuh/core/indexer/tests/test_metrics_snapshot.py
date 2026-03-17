# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
Unit tests for MetricsSnapshotTasks._collect_agents and _collect_comms_all_nodes.
"""

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

mocked_modules = {
    "wazuh.core.agent": MagicMock(),
    "wazuh.core.common": MagicMock(),
    "wazuh.core.configuration": MagicMock(),
    "wazuh.core.stats": MagicMock(),
    "wazuh.core.utils": MagicMock(),
    "wazuh.core.InputValidator": MagicMock(),
    "wazuh.core.cluster": MagicMock(),
    "wazuh.core.cluster.utils": MagicMock(),
    "wazuh.core.cluster.dapi": MagicMock(),
    "wazuh.core.cluster.dapi.dapi": MagicMock(),
    "wazuh.core.exception": MagicMock(),
    "wazuh.core.wazuh_queue": MagicMock(),
    "wazuh.core.wazuh_socket": MagicMock(),
    "wazuh.core.wdb": MagicMock(),
    "wazuh.core.wdb_http": MagicMock(),
    "wazuh.rbac": MagicMock(),
    "wazuh.rbac.utils": MagicMock(),
    "wazuh.stats": MagicMock(),
}

with patch.dict(sys.modules, mocked_modules):
    import wazuh.core.indexer.metrics_snapshot as _metrics_snapshot_module
    from wazuh.core.indexer.metrics_snapshot import MetricsSnapshotTasks

# Ensure the module is accessible as an attribute of its parent package so that
# unittest.mock.patch can resolve dotted targets like
# "wazuh.core.indexer.metrics_snapshot.DistributedAPI".
import wazuh.core.indexer as _indexer_pkg

_indexer_pkg.metrics_snapshot = _metrics_snapshot_module


TIMESTAMP = "2026-03-17T10:00:00.000Z"

REMOTED_STATS = {
    "queue_size": 10,
    "total_queue_size": 100,
    "tcp_sessions": 5,
    "evt_count": 1000,
    "ctrl_msg_count": 200,
    "discarded_count": 3,
    "sent_bytes": 512000,
    "recv_bytes": 256000,
    "dequeued_after_close": 1,
    "ctrl_msg_queue_usage": 0.15,
    "ctrl_msg_queue_inserted": 210,
    "ctrl_msg_queue_replaced": 8,
    "ctrl_msg_processed": 202,
}

CLUSTER_ITEMS = {
    "intervals": {"master": {"metrics_frequency": 600, "metrics_bulk_size": 100}}
}


def _make_server(node_name="master-node", node_type="master", workers=None):
    """Build a minimal mock server object."""
    server = MagicMock()
    server.configuration = {"node_name": node_name, "node_type": node_type}
    server.clients = workers or {}
    server.setup_task_logger.return_value = MagicMock()
    return server


def _make_tasks(server=None, cluster_items=None):
    """Instantiate MetricsSnapshotTasks with sensible defaults."""
    if server is None:
        server = _make_server()
    return MetricsSnapshotTasks(
        server=server, cluster_items=cluster_items or CLUSTER_ITEMS
    )


def _make_dapi_result(items):
    """Return a mock AffectedItemsWazuhResult with the given affected_items list."""
    result = MagicMock()
    result.affected_items = items
    return result


# ---------------------------------------------------------------------------
# _collect_agents
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
async def test_collect_agents(mock_wazuh_db_query_agents):
    mock_server = MagicMock()
    mock_server.configuration.get.side_effect = lambda k, d: (
        "test_node" if k == "node_name" else "worker"
    )

    mock_query_instance = MagicMock()
    mock_query_instance.run.return_value = {
        "items": [
            {"id": "001", "name": "ubuntu-agent"},
            {"id": "002", "name": "windows-agent"},
        ]
    }
    mock_wazuh_db_query_agents.return_value = mock_query_instance

    task = MetricsSnapshotTasks(server=mock_server, cluster_items=CLUSTER_ITEMS)
    TEST_TIMESTAMP = "2026-03-13T10:00:00Z"

    result = await task._collect_agents(TEST_TIMESTAMP)

    mock_wazuh_db_query_agents.assert_called_once_with(limit=None)

    assert len(result) == 2
    for agent_doc in result:
        assert agent_doc["@timestamp"] == TEST_TIMESTAMP
        assert agent_doc["wazuh.cluster.node_name"] == "test_node"
        assert agent_doc["wazuh.cluster.node_type"] == "worker"
        assert "id" in agent_doc
        assert "name" in agent_doc


# ---------------------------------------------------------------------------
# _collect_comms_all_nodes
# ---------------------------------------------------------------------------


class TestCollectCommsAllNodes:
    """Tests for MetricsSnapshotTasks._collect_comms_all_nodes."""

    @pytest.mark.asyncio
    async def test_single_master_node_injects_metadata(self):
        """Master-only cluster: metadata fields are injected into the document."""
        tasks = _make_tasks(
            server=_make_server(node_name="master-node", node_type="master")
        )

        dapi_result = _make_dapi_result([dict(REMOTED_STATS)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.DistributedAPI",
            return_value=AsyncMock(
                distribute_function=AsyncMock(return_value=dapi_result)
            ),
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        assert len(docs) == 1
        doc = docs[0]
        assert doc["@timestamp"] == TIMESTAMP
        assert doc["wazuh.cluster.node_name"] == "master-node"
        assert doc["wazuh.cluster.node_type"] == "master"

    @pytest.mark.asyncio
    async def test_stats_fields_are_included_in_document(self):
        """All remoted stats fields are present in the returned document."""
        tasks = _make_tasks()

        dapi_result = _make_dapi_result([dict(REMOTED_STATS)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.DistributedAPI",
            return_value=AsyncMock(
                distribute_function=AsyncMock(return_value=dapi_result)
            ),
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        assert len(docs) == 1
        for field, value in REMOTED_STATS.items():
            assert docs[0][field] == value

    @pytest.mark.asyncio
    async def test_worker_node_type_injected(self):
        """Worker node type comes from the worker handler, not the master configuration."""
        worker_handler = MagicMock()
        worker_handler.get_node.return_value = {"type": "worker"}

        server = _make_server(
            node_name="master-node",
            node_type="master",
            workers={"worker-node": worker_handler},
        )
        tasks = _make_tasks(server=server)

        master_result = _make_dapi_result([dict(REMOTED_STATS)])
        worker_result = _make_dapi_result([dict(REMOTED_STATS)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.DistributedAPI",
            side_effect=[
                AsyncMock(distribute_function=AsyncMock(return_value=r))
                for r in [master_result, worker_result]
            ],
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        assert len(docs) == 2
        node_types = {
            doc["wazuh.cluster.node_name"]: doc["wazuh.cluster.node_type"]
            for doc in docs
        }
        assert node_types["master-node"] == "master"
        assert node_types["worker-node"] == "worker"

    @pytest.mark.asyncio
    async def test_empty_affected_items_produces_no_document(self):
        """If DAPI returns no items for a node, no document is added."""
        tasks = _make_tasks()

        dapi_result = _make_dapi_result([])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.DistributedAPI",
            return_value=AsyncMock(
                distribute_function=AsyncMock(return_value=dapi_result)
            ),
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        assert docs == []

    @pytest.mark.asyncio
    async def test_node_failure_is_logged_and_skipped(self):
        """If DAPI raises for one node, the error is logged and remaining nodes are collected."""
        worker_handler = MagicMock()
        worker_handler.get_node.return_value = {"type": "worker"}

        server = _make_server(
            node_name="master-node",
            node_type="master",
            workers={"worker-node": worker_handler},
        )
        tasks = _make_tasks(server=server)

        worker_result = _make_dapi_result([dict(REMOTED_STATS)])

        failing_dapi = AsyncMock()
        failing_dapi.distribute_function.side_effect = RuntimeError(
            "connection refused"
        )
        succeeding_dapi = AsyncMock()
        succeeding_dapi.distribute_function.return_value = worker_result

        with patch(
            "wazuh.core.indexer.metrics_snapshot.DistributedAPI",
            side_effect=[failing_dapi, succeeding_dapi],
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        assert len(docs) == 1
        assert docs[0]["wazuh.cluster.node_name"] == "worker-node"
        tasks.logger.exception.assert_called_once()

    @pytest.mark.asyncio
    async def test_dapi_called_with_correct_kwargs(self):
        """DistributedAPI is called with the correct f, f_kwargs, and request_type."""
        tasks = _make_tasks(
            server=_make_server(node_name="master-node", node_type="master")
        )

        dapi_result = _make_dapi_result([dict(REMOTED_STATS)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.DistributedAPI",
            return_value=AsyncMock(
                distribute_function=AsyncMock(return_value=dapi_result)
            ),
        ) as MockDAPI:
            await tasks._collect_comms_all_nodes(TIMESTAMP)

        MockDAPI.assert_called_once()
        call_kwargs = MockDAPI.call_args.kwargs
        assert call_kwargs["f_kwargs"]["daemons_list"] == ["wazuh-manager-remoted"]
        assert call_kwargs["f_kwargs"]["node_list"] == ["master-node"]
        assert call_kwargs["request_type"] == "distributed_master"
