# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
Unit tests for MetricsSnapshotTasks.

Covered cases
-------------
_collect_agents / _collect_comms_all_nodes  (pre-existing)
TestAgentFieldMapping                        – all normalized agent fields present and typed correctly
TestMetadataInjection                        – @timestamp, wazuh.cluster.node, wazuh.cluster.name in every document
TestRunMetricsSnapshot                       – frequency=0 early-exit; frequency<600 clamped to 600
TestDisconnectionTimeOmission                – wazuh.agent.disconnected_at absent when disconnection_time is 0
TestBulkActionShape                          – _op_type: create on every action sent to async_bulk
"""

import asyncio
import sys
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# opensearchpy must be mocked before any wazuh.core.indexer module is imported
# because wazuh.core.indexer.indexer imports AsyncOpenSearch at the top level.
_mock_opensearchpy = MagicMock()
_mock_opensearchpy.__path__ = []

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

import wazuh.core.indexer as _indexer_pkg

_indexer_pkg.metrics_snapshot = _metrics_snapshot_module
_indexer_pkg.metrics = _metrics_module

sys.modules.setdefault("wazuh.core.indexer.metrics", _metrics_module)
sys.modules.setdefault("wazuh.core.indexer.metrics_snapshot", _metrics_snapshot_module)


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


def _make_server(node_name="node01", workers=None):
    """Build a minimal mock server object.

    Parameters
    ----------
    node_name : str
        Identifying name of the node (maps to wazuh.cluster.node).
        Distinct from cluster_name, which is shared across all nodes.
    workers : dict | None
        Map of worker node names to their handler mocks.
    """
    server = MagicMock()
    server.configuration = {
        "node_name": node_name,  # node identifier → wazuh.cluster.node
        "cluster_name": "wazuh",  # cluster name    → wazuh.cluster.name
    }
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
    mock_server = _make_server(node_name="node01")

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
        # wazuh.cluster.node carries the node_name identifier
        assert agent_doc["wazuh.cluster.node"] == "node01"
        # wazuh.cluster.name carries the cluster name, distinct from the node name
        assert agent_doc["wazuh.cluster.name"] == "wazuh"
        assert "wazuh.agent.id" in agent_doc
        assert "wazuh.agent.name" in agent_doc


# ---------------------------------------------------------------------------
# _collect_comms_all_nodes
# ---------------------------------------------------------------------------

# Normalized field names expected in every comms document
EXPECTED_COMMS_FIELDS = {
    "queue.usage",
    "queue.capacity",
    "tcp.sessions",
    "discarded.total",
    "events.total",
    "network.egress.bytes",
    "network.ingress.bytes",
    "messages.total",
    "messages.control.dropped_on_close.total",
    "messages.control.usage",
    "messages.control.received.total",
    "messages.control.replaced.total",
    "messages.control.processed.total",
    "events.module",
    "@timestamp",
    "wazuh.cluster.name",
    "wazuh.cluster.node",
    "wazuh.schema.version",
}


class TestCollectCommsAllNodes:
    """Tests for MetricsSnapshotTasks._collect_comms_all_nodes."""

    @pytest.mark.asyncio
    async def test_single_master_node_injects_metadata(self):
        """Master-only cluster: metadata fields are injected into the document."""
        tasks = _make_tasks(server=_make_server(node_name="node01"))

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
        assert doc["wazuh.cluster.node"] == "node01"
        assert doc["wazuh.cluster.name"] == "wazuh"

    @pytest.mark.asyncio
    async def test_stats_fields_are_included_in_document(self):
        """All normalized comms fields are present in the returned document."""
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
        for field in EXPECTED_COMMS_FIELDS:
            assert field in docs[0], f"Missing normalized field: {field}"

    @pytest.mark.asyncio
    async def test_worker_node_injects_its_own_node_name(self):
        """Worker node documents carry their own node name in wazuh.cluster.node."""
        worker_handler = MagicMock()

        server = _make_server(
            node_name="node01",
            workers={"node02": worker_handler},
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
        node_names = {doc["wazuh.cluster.node"] for doc in docs}
        assert "node01" in node_names
        assert "node02" in node_names

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

        server = _make_server(
            node_name="node01",
            workers={"node02": worker_handler},
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
        assert docs[0]["wazuh.cluster.node"] == "node02"
        tasks.logger.exception.assert_called_once()

    @pytest.mark.asyncio
    async def test_dapi_called_with_correct_kwargs(self):
        """DistributedAPI is called with the correct f, f_kwargs, and request_type."""
        tasks = _make_tasks(server=_make_server(node_name="node01"))

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
        assert call_kwargs["f_kwargs"]["node_list"] == ["node01"]
        assert call_kwargs["request_type"] == "distributed_master"


# ---------------------------------------------------------------------------
# Agent field mapping
# ---------------------------------------------------------------------------

# Representative raw agent document as returned by WazuhDBQueryAgents.run()["items"].
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
    "manager": "node01",
    "dateAdd": "2026-01-01T00:00:00Z",
    "group": ["default"],
    "mergedSum": "abcdef1234567890",
    "configSum": "0987654321fedcba",
    "node_name": "node01",
    "lastKeepAlive": "2026-03-17T10:00:00Z",
    "disconnection_time": 12345,
    "registerIP": "10.0.1.5",
    "group_config_status": "synced",
    "status_code": 0,
}

# Normalized field names expected in the output document after _normalize_agent_doc().
# Dropped by agreement: os.major, os.minor, os.codename, os.build, manager, node_name, host.
EXPECTED_AGENT_FIELDS = {
    "@timestamp",
    "wazuh.agent.id",
    "wazuh.agent.name",
    "wazuh.agent.version",
    "wazuh.agent.groups",
    "wazuh.agent.host.ip",
    "wazuh.agent.register.ip",
    "wazuh.agent.status",
    "wazuh.agent.status_code",
    "wazuh.agent.registered_at",
    "wazuh.agent.last_seen",
    "wazuh.agent.disconnected_at",
    "wazuh.agent.config.hash.md5",
    "wazuh.agent.config.group.synced",
    "wazuh.agent.config.group.hash.md5",
    "wazuh.agent.host.architecture",
    "wazuh.agent.host.os.name",
    "wazuh.agent.host.os.version",
    "wazuh.agent.host.os.platform",
    "wazuh.agent.host.os.full",
    "wazuh.cluster.name",
    "wazuh.cluster.node",
    "wazuh.schema.version",
}


class TestAgentFieldMapping:
    """TC-1 – All expected normalized agent fields are present and correctly typed."""

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_all_fields_present(self, mock_wazuh_db_query_agents):
        """Every normalized field key exists in the output document."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [dict(AGENT_DOC_FULL)]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        assert len(docs) == 1
        doc = docs[0]
        missing = EXPECTED_AGENT_FIELDS - doc.keys()
        assert not missing, f"Missing normalized fields: {missing}"

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_field_types(self, mock_wazuh_db_query_agents):
        """Spot-check field types: normalized string/bool/list fields have correct types."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [dict(AGENT_DOC_FULL)]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        doc = docs[0]
        assert isinstance(doc["wazuh.agent.id"], str)
        assert isinstance(doc["wazuh.agent.name"], str)
        assert isinstance(doc["wazuh.agent.status"], str)
        assert isinstance(doc["wazuh.agent.config.group.synced"], bool)
        assert isinstance(doc["wazuh.agent.groups"], list)
        assert isinstance(doc["@timestamp"], str)
        assert isinstance(doc["wazuh.cluster.node"], str)
        assert isinstance(doc["wazuh.cluster.name"], str)
        assert isinstance(doc["wazuh.schema.version"], str)

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_multiple_agents_all_have_expected_fields(
        self, mock_wazuh_db_query_agents
    ):
        """Normalization applies to every document in a multi-agent result."""
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
            assert not missing, (
                f"Missing normalized fields in doc {doc.get('wazuh.agent.id')}: {missing}"
            )

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_register_ip_any_converted_to_cidr(self, mock_wazuh_db_query_agents):
        """registerIP='any' is converted to '0.0.0.0/0' for the ip field type."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [{**AGENT_DOC_FULL, "registerIP": "any"}]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        assert docs[0]["wazuh.agent.register.ip"] == "0.0.0.0/0"

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_register_ip_real_value_preserved(self, mock_wazuh_db_query_agents):
        """A real IP for registerIP passes through unchanged."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [{**AGENT_DOC_FULL, "registerIP": "10.0.1.5"}]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        assert docs[0]["wazuh.agent.register.ip"] == "10.0.1.5"

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_register_ip_empty_field_omitted(self, mock_wazuh_db_query_agents):
        """An empty/missing registerIP does not produce an empty string in the output."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [{**AGENT_DOC_FULL, "registerIP": ""}]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        assert "wazuh.agent.register.ip" not in docs[0]

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_group_config_status_synced_maps_to_true(
        self, mock_wazuh_db_query_agents
    ):
        """group_config_status='synced' maps to boolean True."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [{**AGENT_DOC_FULL, "group_config_status": "synced"}]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        assert docs[0]["wazuh.agent.config.group.synced"] is True

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_group_config_status_not_synced_maps_to_false(
        self, mock_wazuh_db_query_agents
    ):
        """group_config_status='not synced' maps to boolean False."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [{**AGENT_DOC_FULL, "group_config_status": "not synced"}]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        assert docs[0]["wazuh.agent.config.group.synced"] is False

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_redundant_raw_fields_dropped(self, mock_wazuh_db_query_agents):
        """Raw fields (manager, node_name, id, etc.) are absent after normalization."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [dict(AGENT_DOC_FULL)]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        doc = docs[0]
        for dropped in (
            "manager",
            "node_name",
            "id",
            "name",
            "ip",
            "status",
            "group",
            "mergedSum",
            "configSum",
            "dateAdd",
            "lastKeepAlive",
            "group_config_status",
            "status_code",
        ):
            assert dropped not in doc, (
                f"Raw field '{dropped}' should have been normalized away"
            )


# ---------------------------------------------------------------------------
# Metadata injection
# ---------------------------------------------------------------------------


class TestMetadataInjection:
    """TC-2 – @timestamp, wazuh.cluster.node, wazuh.cluster.name in every document."""

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_agent_docs_have_all_metadata_fields(
        self, mock_wazuh_db_query_agents
    ):
        """All three metadata fields are injected into every agent document."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [{"id": "001"}, {"id": "002"}, {"id": "003"}]
        }

        server = _make_server(node_name="node01")
        tasks = _make_tasks(server=server)
        docs = await tasks._collect_agents(TIMESTAMP)

        for doc in docs:
            assert "@timestamp" in doc, f"@timestamp missing in doc {doc}"
            assert "wazuh.cluster.node" in doc
            assert "wazuh.cluster.name" in doc

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_agent_metadata_values_match_server_config(
        self, mock_wazuh_db_query_agents
    ):
        """Metadata values are sourced from server.configuration."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [{"id": "001"}]
        }

        server = _make_server(node_name="node01")
        tasks = _make_tasks(server=server)
        docs = await tasks._collect_agents(TIMESTAMP)

        doc = docs[0]
        assert doc["@timestamp"] == TIMESTAMP
        assert doc["wazuh.cluster.node"] == "node01"
        assert doc["wazuh.cluster.name"] == "wazuh"

    @pytest.mark.asyncio
    async def test_comms_docs_have_all_metadata_fields(self):
        """All three metadata fields are injected into every comms document."""
        tasks = _make_tasks(server=_make_server(node_name="node01"))
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
            assert "wazuh.cluster.node" in doc
            assert "wazuh.cluster.name" in doc

    @pytest.mark.asyncio
    async def test_comms_metadata_values_match_server_config(self):
        """Comms metadata values are sourced from server.configuration."""
        tasks = _make_tasks(server=_make_server(node_name="node01"))
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
        assert doc["wazuh.cluster.node"] == "node01"
        assert doc["wazuh.cluster.name"] == "wazuh"

    @pytest.mark.asyncio
    async def test_events_module_is_remoted_in_comms(self):
        """events.module is always set to 'remoted' in comms documents."""
        tasks = _make_tasks()
        dapi_result = _make_dapi_result([dict(REMOTED_STATS)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.DistributedAPI",
            return_value=AsyncMock(
                distribute_function=AsyncMock(return_value=dapi_result)
            ),
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        assert docs[0]["events.module"] == "remoted"


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
        tasks = _make_tasks()

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
    """TC-5 – wazuh.agent.disconnected_at is absent when disconnection_time is 0."""

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_disconnection_time_zero_is_absent(self, mock_wazuh_db_query_agents):
        """TC-5: WazuhDBQueryAgents strips disconnection_time=0; normalized field must not appear."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [{"id": "001", "name": "agent-active", "status": "active"}]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        assert "wazuh.agent.disconnected_at" not in docs[0]

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_nonzero_disconnection_time_is_preserved(
        self, mock_wazuh_db_query_agents
    ):
        """A non-zero disconnection_time maps to wazuh.agent.disconnected_at."""
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

        assert docs[0]["wazuh.agent.disconnected_at"] == 19345809

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_mixed_agents_disconnection_time_handled_per_agent(
        self, mock_wazuh_db_query_agents
    ):
        """Active (no key) and disconnected (non-zero value) agents are handled independently."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [
                {"id": "001", "status": "active"},
                {"id": "002", "status": "disconnected", "disconnection_time": 5000},
            ]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        active_doc = next(d for d in docs if d.get("wazuh.agent.id") == "001")
        disconnected_doc = next(d for d in docs if d.get("wazuh.agent.id") == "002")

        assert "wazuh.agent.disconnected_at" not in active_doc
        assert disconnected_doc["wazuh.agent.disconnected_at"] == 5000


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
            {
                "wazuh.agent.id": "001",
                "@timestamp": TIMESTAMP,
                "wazuh.cluster.node": "node01",
            },
            {
                "wazuh.agent.id": "002",
                "@timestamp": TIMESTAMP,
                "wazuh.cluster.node": "node01",
            },
            {
                "wazuh.agent.id": "003",
                "@timestamp": TIMESTAMP,
                "wazuh.cluster.node": "node01",
            },
        ]

        captured_actions = []

        async def _capture_bulk(client, actions, **kwargs):
            captured_actions.extend(list(actions))
            return (len(captured_actions), 0)

        with patch(
            "wazuh.core.indexer.metrics.async_bulk",
            new_callable=AsyncMock,
            side_effect=_capture_bulk,
        ):
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

        docs = [{"wazuh.agent.id": "001"}]
        captured_actions = []

        async def _capture_bulk(client, actions, **kwargs):
            captured_actions.extend(list(actions))
            return (1, 0)

        with patch(
            "wazuh.core.indexer.metrics.async_bulk",
            new_callable=AsyncMock,
            side_effect=_capture_bulk,
        ):
            await metrics_index.bulk_index("wazuh-metrics-agents", docs, bulk_size=100)

        assert captured_actions[0]["_index"] == "wazuh-metrics-agents"
        assert captured_actions[0]["_op_type"] == "create"

    @pytest.mark.asyncio
    async def test_bulk_actions_source_contains_original_document(self):
        """_source in each action is the original document dict."""
        mock_client = AsyncMock()
        metrics_index = MetricsIndex(client=mock_client)

        docs = [
            {"wazuh.agent.id": "001", "@timestamp": TIMESTAMP},
            {"wazuh.agent.id": "002", "@timestamp": TIMESTAMP},
        ]
        captured_actions = []

        async def _capture_bulk(client, actions, **kwargs):
            captured_actions.extend(list(actions))
            return (2, 0)

        with patch(
            "wazuh.core.indexer.metrics.async_bulk",
            new_callable=AsyncMock,
            side_effect=_capture_bulk,
        ):
            await metrics_index.bulk_index("wazuh-metrics-agents", docs, bulk_size=100)

        for i, action in enumerate(captured_actions):
            assert action["_source"] == docs[i]


# ---------------------------------------------------------------------------
# __init__ fallback paths
# ---------------------------------------------------------------------------


class TestInit:
    """Tests for MetricsSnapshotTasks.__init__ fallback and warning paths."""

    def test_no_setup_task_logger_uses_logging_getLogger(self):
        """server without setup_task_logger falls back to logging.getLogger."""
        server = MagicMock(spec=[])
        server.configuration = {"node_name": "node01", "cluster_name": "wazuh"}

        with patch("wazuh.core.indexer.metrics_snapshot.logging") as mock_logging:
            tasks = MetricsSnapshotTasks(server=server, cluster_items=CLUSTER_ITEMS)

        mock_logging.getLogger.assert_called_once_with("wazuh")
        assert tasks.logger is mock_logging.getLogger.return_value

    def test_none_server_uses_logging_getLogger(self):
        """server=None also triggers the getLogger fallback."""
        with patch("wazuh.core.indexer.metrics_snapshot.logging") as mock_logging:
            tasks = MetricsSnapshotTasks(server=None, cluster_items=CLUSTER_ITEMS)

        mock_logging.getLogger.assert_called_once_with("wazuh")
        assert tasks.logger is mock_logging.getLogger.return_value

    def test_missing_metrics_frequency_logs_warning(self):
        """A warning is emitted when metrics_frequency is absent from config."""
        cluster_items_no_freq = {"intervals": {"master": {"metrics_bulk_size": 100}}}
        tasks = _make_tasks(cluster_items=cluster_items_no_freq)

        tasks.logger.warning.assert_any_call(
            f"metrics_frequency not found in cluster configuration. "
            f"Using default: {MetricsSnapshotTasks.DEFAULT_METRICS_FREQUENCY}"
        )
        assert tasks.frequency == MetricsSnapshotTasks.DEFAULT_METRICS_FREQUENCY

    def test_missing_metrics_bulk_size_logs_warning(self):
        """A warning is emitted when metrics_bulk_size is absent from config."""
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
# _collect_and_index
# ---------------------------------------------------------------------------


def _patch_collect_and_index(
    tasks, mock_indexer, agent_docs=None, comms_docs=None, collect_agents_override=None
):
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
        agent_docs = [{"wazuh.agent.id": "001", "@timestamp": TIMESTAMP}]
        comms_docs = [{"events.total": 1000, "@timestamp": TIMESTAMP}]

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
        """bulk_index is called with 'wazuh-metrics-agents' and the normalized agent docs."""
        agent_docs = [{"wazuh.agent.id": "001"}]

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
        """bulk_index is called with 'wazuh-metrics-comms' and the normalized comms docs."""
        comms_docs = [{"events.total": 1000}]

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
        parsed = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        assert parsed is not None
