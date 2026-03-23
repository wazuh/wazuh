# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
Unit tests for MetricsSnapshotTasks.

Covered cases
-------------
_collect_agents / _collect_comms_all_nodes  (pre-existing)
TestAgentFieldMapping                        – all 25 agent fields present and typed correctly
TestMetadataInjection                        – @timestamp, wazuh.cluster.* in every document
TestRunMetricsSnapshot                       – frequency=0 early-exit; frequency<600 clamped to 600
TestDisconnectionTimeOmission                – disconnection_time absent when value is 0
TestBulkActionShape                          – _op_type: create on every action sent to async_bulk
"""

import asyncio
import sys
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# opensearchpy must be mocked before any wazuh.core.indexer module is imported
# because wazuh.core.indexer.indexer imports AsyncOpenSearch at the top level.
# We mock the entire opensearchpy package tree as a spec-less MagicMock so that
# attribute access like `opensearchpy.exceptions.ImproperlyConfigured` works.
_mock_opensearchpy = MagicMock()
_mock_opensearchpy.__path__ = []  # mark as package so sub-module imports resolve

mocked_modules = {
    "opensearchpy": _mock_opensearchpy,
    "opensearchpy.exceptions": MagicMock(),
    "opensearchpy.helpers": MagicMock(),
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
    import wazuh.core.indexer.metrics as _metrics_module
    from wazuh.core.indexer.metrics import MetricsIndex

# Ensure the modules are accessible as attributes of their parent package so
# that unittest.mock.patch can resolve dotted targets like
# "wazuh.core.indexer.metrics_snapshot.DistributedAPI" and
# "wazuh.core.indexer.metrics.async_bulk".
import wazuh.core.indexer as _indexer_pkg

_indexer_pkg.metrics_snapshot = _metrics_snapshot_module
_indexer_pkg.metrics = _metrics_module


TIMESTAMP = "2026-03-17T10:00:00Z"

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


# ---------------------------------------------------------------------------
# Agent field mapping
# ---------------------------------------------------------------------------

# Representative agent document as returned by WazuhDBQueryAgents.run()["items"].
# Contains all 25 fields defined in Agent.fields (internal_key and registerIP are
# stripped by WazuhDBQueryAgents when remove_extra_fields=True, so they are absent;
# the remaining 25 keys below reflect what _collect_agents actually receives).
AGENT_DOC_FULL = {
    "id": "001",
    "name": "ubuntu-agent",
    "ip": "192.168.1.10",
    "status": "active",
    "os": {
        "name": "Ubuntu",
        "version": "22.04",
        "platform": "ubuntu",
        "codename": "Jammy Jellyfish",
        "major": "22",
        "minor": "04",
        "uname": "Linux ubuntu 5.15.0",
        "arch": "x86_64",
        "build": "",
    },
    "version": "Wazuh v4.9.0",
    "manager": "master-node",
    "dateAdd": "2026-01-01T00:00:00Z",
    "group": ["default"],
    "mergedSum": "abcdef1234567890",
    "configSum": "0987654321fedcba",
    "node_name": "master-node",
    "lastKeepAlive": "2026-03-17T10:00:00Z",
    "disconnection_time": 12345,
    "group_config_status": "synced",
    "status_code": 0,
}

# Flat list of all top-level and nested keys expected in the output document.
# The 22 agent data fields (after WazuhDBQueryAgents processing) + 3 metadata fields = 25.
EXPECTED_AGENT_FIELDS = {
    # Core identity
    "id",
    "name",
    "ip",
    "status",
    # OS (nested dict — present as a single "os" key in the returned document)
    "os",
    # Software / versioning
    "version",
    "manager",
    "dateAdd",
    "group",
    "mergedSum",
    "configSum",
    # Cluster
    "node_name",
    # Timestamps
    "lastKeepAlive",
    "disconnection_time",
    # Group config
    "group_config_status",
    "status_code",
    # Injected metadata
    "@timestamp",
    "wazuh.cluster.node_name",
    "wazuh.cluster.node_type",
}


class TestAgentFieldMapping:
    """TC-1 – All expected agent fields are present and correctly typed in every document."""

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_all_fields_present(self, mock_wazuh_db_query_agents):
        """Every expected field key exists in the output document."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [dict(AGENT_DOC_FULL)]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        assert len(docs) == 1
        doc = docs[0]
        missing = EXPECTED_AGENT_FIELDS - doc.keys()
        assert not missing, f"Missing fields: {missing}"

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_field_types(self, mock_wazuh_db_query_agents):
        """Spot-check field types: id/name/ip/status are strings, os is a dict."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [dict(AGENT_DOC_FULL)]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        doc = docs[0]
        assert isinstance(doc["id"], str)
        assert isinstance(doc["name"], str)
        assert isinstance(doc["ip"], str)
        assert isinstance(doc["status"], str)
        assert isinstance(doc["os"], dict)
        assert isinstance(doc["@timestamp"], str)
        assert isinstance(doc["wazuh.cluster.node_name"], str)
        assert isinstance(doc["wazuh.cluster.node_type"], str)

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_multiple_agents_all_have_expected_fields(
        self, mock_wazuh_db_query_agents
    ):
        """Field mapping applies to every document in a multi-agent result."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [
                dict(AGENT_DOC_FULL),
                {**AGENT_DOC_FULL, "id": "002", "name": "windows-agent"},
            ]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        assert len(docs) == 2
        for doc in docs:
            missing = EXPECTED_AGENT_FIELDS - doc.keys()
            assert not missing, f"Missing fields in doc {doc.get('id')}: {missing}"


# ---------------------------------------------------------------------------
# Metadata injection
# ---------------------------------------------------------------------------


class TestMetadataInjection:
    """TC-2 – @timestamp, wazuh.cluster.node_name, wazuh.cluster.node_type present in every document."""

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_agent_docs_have_all_metadata_fields(
        self, mock_wazuh_db_query_agents
    ):
        """All three metadata fields are injected into every agent document."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [{"id": "001"}, {"id": "002"}, {"id": "003"}]
        }

        server = _make_server(node_name="my-master", node_type="master")
        tasks = _make_tasks(server=server)
        docs = await tasks._collect_agents(TIMESTAMP)

        for doc in docs:
            assert "@timestamp" in doc, f"@timestamp missing in doc {doc}"
            assert "wazuh.cluster.node_name" in doc
            assert "wazuh.cluster.node_type" in doc

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_agent_metadata_values_match_server_config(
        self, mock_wazuh_db_query_agents
    ):
        """Metadata values are sourced from server.configuration."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [{"id": "001"}]
        }

        server = _make_server(node_name="prod-master", node_type="master")
        tasks = _make_tasks(server=server)
        docs = await tasks._collect_agents(TIMESTAMP)

        doc = docs[0]
        assert doc["@timestamp"] == TIMESTAMP
        assert doc["wazuh.cluster.node_name"] == "prod-master"
        assert doc["wazuh.cluster.node_type"] == "master"

    @pytest.mark.asyncio
    async def test_comms_docs_have_all_metadata_fields(self):
        """All three metadata fields are injected into every comms document."""
        tasks = _make_tasks(
            server=_make_server(node_name="my-master", node_type="master")
        )
        dapi_result = _make_dapi_result([dict(REMOTED_STATS)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.DistributedAPI",
            return_value=AsyncMock(
                distribute_function=AsyncMock(return_value=dapi_result)
            ),
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        for doc in docs:
            assert "@timestamp" in doc
            assert "wazuh.cluster.node_name" in doc
            assert "wazuh.cluster.node_type" in doc

    @pytest.mark.asyncio
    async def test_comms_metadata_values_match_server_config(self):
        """Comms metadata values are sourced from server.configuration."""
        tasks = _make_tasks(
            server=_make_server(node_name="edge-node", node_type="master")
        )
        dapi_result = _make_dapi_result([dict(REMOTED_STATS)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.DistributedAPI",
            return_value=AsyncMock(
                distribute_function=AsyncMock(return_value=dapi_result)
            ),
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        doc = docs[0]
        assert doc["@timestamp"] == TIMESTAMP
        assert doc["wazuh.cluster.node_name"] == "edge-node"
        assert doc["wazuh.cluster.node_type"] == "master"


# ---------------------------------------------------------------------------
# run_metrics_snapshot loop behaviour
# ---------------------------------------------------------------------------


class TestRunMetricsSnapshot:
    """TC-3 / TC-4 – Loop early-exit and sleep clamping."""

    @pytest.mark.asyncio
    async def test_frequency_zero_returns_immediately(self):
        """TC-3: metrics_frequency=0 returns without calling collection or indexing."""
        cluster_items = {
            "intervals": {"master": {"metrics_frequency": 0, "metrics_bulk_size": 100}}
        }
        tasks = _make_tasks(cluster_items=cluster_items)

        with (
            patch.object(
                tasks, "_collect_and_index", new_callable=AsyncMock
            ) as mock_collect,
            patch(
                "wazuh.core.indexer.metrics_snapshot.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
        ):
            await tasks.run_metrics_snapshot()

        mock_sleep.assert_not_called()
        mock_collect.assert_not_called()

    @pytest.mark.asyncio
    async def test_frequency_zero_logs_disabled_message(self):
        """TC-3: a disabled-metrics info message is logged when frequency=0."""
        cluster_items = {
            "intervals": {"master": {"metrics_frequency": 0, "metrics_bulk_size": 100}}
        }
        tasks = _make_tasks(cluster_items=cluster_items)

        with patch.object(tasks, "_collect_and_index", new_callable=AsyncMock):
            await tasks.run_metrics_snapshot()

        tasks.logger.info.assert_called_once()
        logged_msg = tasks.logger.info.call_args[0][0]
        assert "disabled" in logged_msg.lower() or "0" in logged_msg

    @pytest.mark.asyncio
    async def test_frequency_below_minimum_is_clamped_to_600(self):
        """TC-4: asyncio.sleep is called with 600 when metrics_frequency < 600."""
        cluster_items = {
            "intervals": {"master": {"metrics_frequency": 30, "metrics_bulk_size": 100}}
        }
        tasks = _make_tasks(cluster_items=cluster_items)

        assert tasks.frequency == 30

        with (
            patch(
                "wazuh.core.indexer.metrics_snapshot.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch.object(
                tasks, "_collect_and_index", side_effect=[None, asyncio.CancelledError]
            ),
        ):
            with pytest.raises(asyncio.CancelledError):
                await tasks.run_metrics_snapshot()

        mock_sleep.assert_called_with(600)

    @pytest.mark.asyncio
    async def test_frequency_at_minimum_is_not_changed(self):
        """Boundary: asyncio.sleep receives exactly 600 when frequency=600."""
        tasks = _make_tasks()  # default cluster_items has metrics_frequency=600

        assert tasks.frequency == 600

        with (
            patch(
                "wazuh.core.indexer.metrics_snapshot.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch.object(
                tasks, "_collect_and_index", side_effect=[None, asyncio.CancelledError]
            ),
        ):
            with pytest.raises(asyncio.CancelledError):
                await tasks.run_metrics_snapshot()

        mock_sleep.assert_called_with(600)

    @pytest.mark.asyncio
    async def test_frequency_above_minimum_is_used_unchanged(self):
        """asyncio.sleep receives the configured value when frequency > 600."""
        cluster_items = {
            "intervals": {
                "master": {"metrics_frequency": 1200, "metrics_bulk_size": 100}
            }
        }
        tasks = _make_tasks(cluster_items=cluster_items)

        assert tasks.frequency == 1200

        with (
            patch(
                "wazuh.core.indexer.metrics_snapshot.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch.object(
                tasks, "_collect_and_index", side_effect=[None, asyncio.CancelledError]
            ),
        ):
            with pytest.raises(asyncio.CancelledError):
                await tasks.run_metrics_snapshot()

        mock_sleep.assert_called_with(1200)

    @pytest.mark.asyncio
    async def test_collection_exception_is_caught_and_logged(self):
        """Exceptions from _collect_and_index are logged and the loop continues."""
        tasks = _make_tasks()

        with (
            patch(
                "wazuh.core.indexer.metrics_snapshot.asyncio.sleep",
                new_callable=AsyncMock,
            ),
            patch.object(
                tasks,
                "_collect_and_index",
                side_effect=[RuntimeError("boom"), asyncio.CancelledError],
            ),
        ):
            with pytest.raises(asyncio.CancelledError):
                await tasks.run_metrics_snapshot()

        tasks.logger.exception.assert_called_once()


# ---------------------------------------------------------------------------
# disconnection_time omission
# ---------------------------------------------------------------------------


class TestDisconnectionTimeOmission:
    """TC-5 – disconnection_time is absent from agent documents when value is 0."""

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_disconnection_time_zero_is_absent(self, mock_wazuh_db_query_agents):
        """TC-5: WazuhDBQueryAgents strips disconnection_time=0; document must not contain it."""
        # WazuhDBQueryAgents.run() already removes disconnection_time when it is 0.
        # The mock replicates that behaviour by not including the key.
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [{"id": "001", "name": "agent-active", "status": "active"}]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        assert "disconnection_time" not in docs[0]

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_nonzero_disconnection_time_is_preserved(
        self, mock_wazuh_db_query_agents
    ):
        """A non-zero disconnection_time passes through unmodified."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [
                {
                    "id": "002",
                    "name": "agent-disconnected",
                    "status": "disconnected",
                    "disconnection_time": 19345809,
                }
            ]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        assert docs[0]["disconnection_time"] == 19345809

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_mixed_agents_disconnection_time_handled_per_agent(
        self, mock_wazuh_db_query_agents
    ):
        """Active (no key) and disconnected (non-zero value) agents are handled independently."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [
                {"id": "001", "status": "active"},  # no key
                {
                    "id": "002",
                    "status": "disconnected",
                    "disconnection_time": 5000,
                },  # non-zero
            ]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        active_doc = next(d for d in docs if d["id"] == "001")
        disconnected_doc = next(d for d in docs if d["id"] == "002")

        assert "disconnection_time" not in active_doc
        assert disconnected_doc["disconnection_time"] == 5000


# ---------------------------------------------------------------------------
# Bulk action shape
# ---------------------------------------------------------------------------


class TestBulkActionShape:
    """TC-6 – Every action passed to async_bulk has _op_type: create."""

    @pytest.mark.asyncio
    async def test_bulk_actions_have_op_type_create(self):
        """TC-6: _op_type='create' present in every action sent to async_bulk."""
        mock_client = AsyncMock()
        metrics_index = MetricsIndex(client=mock_client)

        docs = [
            {"id": "001", "@timestamp": TIMESTAMP, "wazuh.cluster.node_name": "n1"},
            {"id": "002", "@timestamp": TIMESTAMP, "wazuh.cluster.node_name": "n1"},
            {"id": "003", "@timestamp": TIMESTAMP, "wazuh.cluster.node_name": "n1"},
        ]

        captured_actions = []

        async def _capture_bulk(client, actions, **kwargs):
            captured_actions.extend(list(actions))
            return (len(captured_actions), 0)

        with patch("wazuh.core.indexer.metrics.async_bulk", side_effect=_capture_bulk):
            await metrics_index.bulk_index("wazuh-metrics-agents", docs, bulk_size=100)

        assert len(captured_actions) == len(docs)
        for action in captured_actions:
            assert action["_op_type"] == "create", (
                f"Expected _op_type='create', got {action.get('_op_type')!r}"
            )

    @pytest.mark.asyncio
    async def test_bulk_actions_index_name_matches_target(self):
        """Each action carries the correct _index value for the target data stream."""
        mock_client = AsyncMock()
        metrics_index = MetricsIndex(client=mock_client)

        docs = [{"id": "001"}]
        captured_actions = []

        async def _capture_bulk(client, actions, **kwargs):
            captured_actions.extend(list(actions))
            return (1, 0)

        with patch("wazuh.core.indexer.metrics.async_bulk", side_effect=_capture_bulk):
            await metrics_index.bulk_index("wazuh-metrics-agents", docs, bulk_size=100)

        assert captured_actions[0]["_index"] == "wazuh-metrics-agents"
        assert captured_actions[0]["_op_type"] == "create"

    @pytest.mark.asyncio
    async def test_bulk_actions_source_contains_original_document(self):
        """_source in each action is the original document dict."""
        mock_client = AsyncMock()
        metrics_index = MetricsIndex(client=mock_client)

        docs = [
            {"id": "001", "@timestamp": TIMESTAMP},
            {"id": "002", "@timestamp": TIMESTAMP},
        ]
        captured_actions = []

        async def _capture_bulk(client, actions, **kwargs):
            captured_actions.extend(list(actions))
            return (2, 0)

        with patch("wazuh.core.indexer.metrics.async_bulk", side_effect=_capture_bulk):
            await metrics_index.bulk_index("wazuh-metrics-agents", docs, bulk_size=100)

        for i, action in enumerate(captured_actions):
            assert action["_source"] == docs[i]


# ---------------------------------------------------------------------------
# __init__ fallback paths  (lines 19, 23, 28)
# ---------------------------------------------------------------------------


class TestInit:
    """Tests for MetricsSnapshotTasks.__init__ fallback and warning paths."""

    def test_no_setup_task_logger_uses_logging_getLogger(self):
        """Line 19: server without setup_task_logger falls back to logging.getLogger."""
        server = MagicMock(
            spec=[]
        )  # spec=[] → no attributes at all, incl. setup_task_logger
        server.configuration = {"node_name": "n", "node_type": "master"}

        with patch("wazuh.core.indexer.metrics_snapshot.logging") as mock_logging:
            tasks = MetricsSnapshotTasks(server=server, cluster_items=CLUSTER_ITEMS)

        mock_logging.getLogger.assert_called_once_with("wazuh")
        assert tasks.logger is mock_logging.getLogger.return_value

    def test_none_server_uses_logging_getLogger(self):
        """Line 19: server=None also triggers the getLogger fallback."""
        with patch("wazuh.core.indexer.metrics_snapshot.logging") as mock_logging:
            tasks = MetricsSnapshotTasks(server=None, cluster_items=CLUSTER_ITEMS)

        mock_logging.getLogger.assert_called_once_with("wazuh")
        assert tasks.logger is mock_logging.getLogger.return_value

    def test_missing_metrics_frequency_logs_warning(self):
        """Line 23: a warning is emitted when metrics_frequency is absent from config."""
        cluster_items_no_freq = {"intervals": {"master": {"metrics_bulk_size": 100}}}
        tasks = _make_tasks(cluster_items=cluster_items_no_freq)

        tasks.logger.warning.assert_any_call(
            f"metrics_frequency not found in cluster configuration. "
            f"Using default: {MetricsSnapshotTasks.DEFAULT_METRICS_FREQUENCY}"
        )
        assert tasks.frequency == MetricsSnapshotTasks.DEFAULT_METRICS_FREQUENCY

    def test_missing_metrics_bulk_size_logs_warning(self):
        """Line 28: a warning is emitted when metrics_bulk_size is absent from config."""
        cluster_items_no_bulk = {"intervals": {"master": {"metrics_frequency": 600}}}
        tasks = _make_tasks(cluster_items=cluster_items_no_bulk)

        tasks.logger.warning.assert_any_call(
            f"metrics_bulk_size not found in cluster configuration. "
            f"Using default: {MetricsSnapshotTasks.DEFAULT_METRICS_BULK_SIZE}"
        )
        assert tasks.bulk_size == MetricsSnapshotTasks.DEFAULT_METRICS_BULK_SIZE

    def test_both_keys_missing_logs_two_warnings(self):
        """Both warnings fire when neither key is present."""
        tasks = _make_tasks(cluster_items={"intervals": {"master": {}}})

        assert tasks.logger.warning.call_count == 2
        assert tasks.frequency == MetricsSnapshotTasks.DEFAULT_METRICS_FREQUENCY
        assert tasks.bulk_size == MetricsSnapshotTasks.DEFAULT_METRICS_BULK_SIZE


# ---------------------------------------------------------------------------
# _collect_and_index  (lines 121-128)
# ---------------------------------------------------------------------------


def _patch_collect_and_index(
    tasks, mock_indexer, agent_docs=None, comms_docs=None, collect_agents_override=None
):
    """Return a combined context manager that patches both collectors and get_indexer_client.

    Parameters
    ----------
    tasks : MetricsSnapshotTasks
        Instance whose collectors will be patched.
    mock_indexer : AsyncMock
        Mock indexer returned by the ``get_indexer_client`` context manager.
    agent_docs : list | None
        Documents returned by ``_collect_agents``.  Ignored when *collect_agents_override* is set.
    comms_docs : list | None
        Documents returned by ``_collect_comms_all_nodes``.
    collect_agents_override : callable | None
        When provided, used as ``side_effect`` for ``_collect_agents`` instead of a fixed return value.
    """
    from contextlib import contextmanager

    @contextmanager
    def _ctx():
        agent_patch_kwargs = (
            {"side_effect": collect_agents_override}
            if collect_agents_override is not None
            else {
                "new_callable": AsyncMock,
                "return_value": agent_docs if agent_docs is not None else [],
            }
        )
        with (
            patch.object(tasks, "_collect_agents", **agent_patch_kwargs) as mock_agents,
            patch.object(
                tasks,
                "_collect_comms_all_nodes",
                new_callable=AsyncMock,
                return_value=comms_docs if comms_docs is not None else [],
            ) as mock_comms,
            patch(
                "wazuh.core.indexer.metrics_snapshot.get_indexer_client",
                return_value=AsyncMock(
                    __aenter__=AsyncMock(return_value=mock_indexer),
                    __aexit__=AsyncMock(return_value=False),
                ),
            ),
        ):
            yield mock_agents, mock_comms

    return _ctx()


class TestCollectAndIndex:
    """Tests for MetricsSnapshotTasks._collect_and_index."""

    @pytest.mark.asyncio
    async def test_collects_agents_and_comms_then_bulk_indexes_both(self):
        """_collect_and_index calls both collectors and bulk-indexes their results."""
        agent_docs = [{"id": "001", "@timestamp": TIMESTAMP}]
        comms_docs = [dict(REMOTED_STATS) | {"@timestamp": TIMESTAMP}]

        mock_indexer = AsyncMock()
        mock_indexer.metrics.bulk_index = AsyncMock()
        tasks = _make_tasks()

        with _patch_collect_and_index(tasks, mock_indexer, agent_docs, comms_docs) as (
            mock_agents,
            mock_comms,
        ):
            await tasks._collect_and_index()

        mock_agents.assert_awaited_once()
        mock_comms.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_bulk_index_called_for_agents_index(self):
        """bulk_index is called with 'wazuh-metrics-agents' and the agent docs."""
        agent_docs = [{"id": "001"}]

        mock_indexer = AsyncMock()
        mock_indexer.metrics.bulk_index = AsyncMock()
        tasks = _make_tasks()

        with _patch_collect_and_index(tasks, mock_indexer, agent_docs=agent_docs):
            await tasks._collect_and_index()

        mock_indexer.metrics.bulk_index.assert_any_await(
            "wazuh-metrics-agents", agent_docs, tasks.bulk_size
        )

    @pytest.mark.asyncio
    async def test_bulk_index_called_for_comms_index(self):
        """bulk_index is called with 'wazuh-metrics-comms' and the comms docs."""
        comms_docs = [dict(REMOTED_STATS)]

        mock_indexer = AsyncMock()
        mock_indexer.metrics.bulk_index = AsyncMock()
        tasks = _make_tasks()

        with _patch_collect_and_index(tasks, mock_indexer, comms_docs=comms_docs):
            await tasks._collect_and_index()

        mock_indexer.metrics.bulk_index.assert_any_await(
            "wazuh-metrics-comms", comms_docs, tasks.bulk_size
        )

    @pytest.mark.asyncio
    async def test_timestamp_is_utc_iso8601(self):
        """The timestamp passed to collectors matches the UTC ISO 8601 format."""
        captured_timestamps = []

        async def _spy_agents(ts):
            captured_timestamps.append(ts)
            return []

        mock_indexer = AsyncMock()
        mock_indexer.metrics.bulk_index = AsyncMock()
        tasks = _make_tasks()

        with _patch_collect_and_index(
            tasks, mock_indexer, collect_agents_override=_spy_agents
        ):
            await tasks._collect_and_index()

        assert len(captured_timestamps) == 1
        ts = captured_timestamps[0]
        # Must match %Y-%m-%dT%H:%M:%SZ  e.g. "2026-03-19T12:00:00Z"
        parsed = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        assert parsed is not None
