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
TestBuildJsonschemaProperties                – nested property schema building
TestOpensearchTemplateToJsonschema           – OpenSearch template to JSON Schema conversion
TestLoadSchema                               – schema loading, caching, and missing-file handling
TestValidateDocuments                        – per-document validation and invalid-doc filtering
"""

import asyncio
import json
import sys
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

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
    from wazuh.core.indexer.metrics_snapshot import (
        MetricsSnapshotTasks,
        _build_jsonschema_properties,
        _opensearch_template_to_jsonschema,
    )
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

# Minimal OpenSearch template fixture used across schema tests.
SAMPLE_TEMPLATE = {
    "index_patterns": ["wazuh-metrics-agents*"],
    "priority": 1,
    "data_stream": {},
    "template": {
        "settings": {},
        "mappings": {
            "dynamic": "strict",
            "date_detection": False,
            "properties": {
                "@timestamp": {"type": "date"},
                "wazuh": {
                    "properties": {
                        "agent": {
                            "properties": {
                                "id": {"type": "keyword"},
                                "name": {"type": "keyword"},
                                "status": {"type": "keyword"},
                                "status_code": {"type": "integer"},
                                "version": {"type": "keyword"},
                            }
                        },
                        "cluster": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "node": {"type": "keyword"},
                            }
                        },
                    }
                },
            },
        },
    },
}


def _make_server(node_name="node01", workers=None):
    """Build a minimal mock server object."""
    server = MagicMock()
    server.configuration = {
        "node_name": node_name,
        "cluster_name": "wazuh",
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


def _deep_keys(doc, prefix=""):
    """Return all dotted-path keys in a nested dict (for field presence checks)."""
    keys = set()
    for k, v in doc.items():
        full = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            keys.update(_deep_keys(v, full))
        else:
            keys.add(full)
    return keys


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
        assert agent_doc["wazuh"]["cluster"]["node"] == "node01"
        assert agent_doc["wazuh"]["cluster"]["name"] == "wazuh"
        assert "id" in agent_doc["wazuh"]["agent"]
        assert "name" in agent_doc["wazuh"]["agent"]


# ---------------------------------------------------------------------------
# _collect_comms_all_nodes
# ---------------------------------------------------------------------------

# Normalized dotted-path field names expected in every comms document
EXPECTED_COMMS_FIELDS = {
    "queue.size",
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
    "event.module",
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

        local_result = _make_dapi_result([dict(REMOTED_STATS)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.get_daemons_stats",
            return_value=local_result,
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        assert len(docs) == 1
        doc = docs[0]
        assert doc["@timestamp"] == TIMESTAMP
        assert doc["wazuh"]["cluster"]["node"] == "node01"
        assert doc["wazuh"]["cluster"]["name"] == "wazuh"

    @pytest.mark.asyncio
    async def test_stats_fields_are_included_in_document(self):
        """All normalized comms fields are present in the returned document."""
        tasks = _make_tasks()

        local_result = _make_dapi_result([dict(REMOTED_STATS)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.get_daemons_stats",
            return_value=local_result,
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        assert len(docs) == 1
        flat_keys = _deep_keys(docs[0])
        for field in EXPECTED_COMMS_FIELDS:
            assert field in flat_keys, f"Missing normalized field: {field}"

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

        with (
            patch(
                "wazuh.core.indexer.metrics_snapshot.get_daemons_stats",
                return_value=master_result,
            ),
            patch(
                "wazuh.core.indexer.metrics_snapshot.DistributedAPI",
                return_value=AsyncMock(
                    distribute_function=AsyncMock(return_value=worker_result)
                ),
            ),
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        assert len(docs) == 2
        node_names = {doc["wazuh"]["cluster"]["node"] for doc in docs}
        assert "node01" in node_names
        assert "node02" in node_names

    @pytest.mark.asyncio
    async def test_empty_affected_items_produces_no_document(self):
        """If stats return no items for the local node, no document is added."""
        tasks = _make_tasks()

        local_result = _make_dapi_result([])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.get_daemons_stats",
            return_value=local_result,
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        assert docs == []

    @pytest.mark.asyncio
    async def test_node_failure_is_logged_and_skipped(self):
        """If local stats raise, the error is logged and remaining nodes are collected."""
        worker_handler = MagicMock()

        server = _make_server(
            node_name="node01",
            workers={"node02": worker_handler},
        )
        tasks = _make_tasks(server=server)

        worker_result = _make_dapi_result([dict(REMOTED_STATS)])

        succeeding_dapi = AsyncMock()
        succeeding_dapi.distribute_function.return_value = worker_result

        with (
            patch(
                "wazuh.core.indexer.metrics_snapshot.get_daemons_stats",
                side_effect=RuntimeError("connection refused"),
            ),
            patch(
                "wazuh.core.indexer.metrics_snapshot.DistributedAPI",
                return_value=succeeding_dapi,
            ),
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        assert len(docs) == 1
        assert docs[0]["wazuh"]["cluster"]["node"] == "node02"
        tasks.logger.exception.assert_called_once()

    @pytest.mark.asyncio
    async def test_dapi_called_for_worker_not_master(self):
        """DistributedAPI is used for worker nodes; local node calls get_daemons_stats directly."""
        worker_handler = MagicMock()
        server = _make_server(node_name="node01", workers={"node02": worker_handler})
        tasks = _make_tasks(server=server)

        local_result = _make_dapi_result([dict(REMOTED_STATS)])
        worker_result = _make_dapi_result([dict(REMOTED_STATS)])

        with (
            patch(
                "wazuh.core.indexer.metrics_snapshot.get_daemons_stats",
                return_value=local_result,
            ) as mock_local,
            patch(
                "wazuh.core.indexer.metrics_snapshot.DistributedAPI",
                return_value=AsyncMock(
                    distribute_function=AsyncMock(return_value=worker_result)
                ),
            ) as MockDAPI,
        ):
            await tasks._collect_comms_all_nodes(TIMESTAMP)

        mock_local.assert_called_once_with(daemons_list=["wazuh-manager-remoted"])
        MockDAPI.assert_called_once()
        call_kwargs = MockDAPI.call_args.kwargs
        assert call_kwargs["f_kwargs"]["daemons_list"] == ["wazuh-manager-remoted"]
        assert call_kwargs["f_kwargs"]["node_list"] == ["node02"]
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
        "arch": "x86_64",
        "build": "",
    },
    "version": "Wazuh v4.9.0",
    "manager": "node01",
    "dateAdd": "2026-01-01T00:00:00Z",
    "group": ["default"],
    "mergedSum": "abcdef1234567890",
    "node_name": "node01",
    "lastKeepAlive": "2026-03-17T10:00:00Z",
    "disconnection_time": 12345,
    "registerIP": "10.0.1.5",
    "group_config_status": "synced",
    "status_code": 0,
}

# Normalized dotted-path field names expected in the output after _normalize_agent_doc().
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
    "wazuh.agent.config.group.synced",
    "wazuh.agent.config.group.hash.md5",
    "wazuh.agent.host.architecture",
    "wazuh.agent.host.os.name",
    "wazuh.agent.host.os.version",
    "wazuh.agent.host.os.platform",
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
        flat_keys = _deep_keys(doc)
        missing = EXPECTED_AGENT_FIELDS - flat_keys
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
        assert isinstance(doc["wazuh"]["agent"]["id"], str)
        assert isinstance(doc["wazuh"]["agent"]["name"], str)
        assert isinstance(doc["wazuh"]["agent"]["status"], str)
        assert isinstance(doc["wazuh"]["agent"]["config"]["group"]["synced"], bool)
        assert isinstance(doc["wazuh"]["agent"]["groups"], list)
        assert isinstance(doc["@timestamp"], str)
        assert isinstance(doc["wazuh"]["cluster"]["node"], str)
        assert isinstance(doc["wazuh"]["cluster"]["name"], str)
        assert isinstance(doc["wazuh"]["schema"]["version"], str)

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
            flat_keys = _deep_keys(doc)
            missing = EXPECTED_AGENT_FIELDS - flat_keys
            assert not missing, (
                f"Missing normalized fields in doc "
                f"{doc.get('wazuh', {}).get('agent', {}).get('id')}: {missing}"
            )

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_register_ip_any_converted_to_cidr(self, mock_wazuh_db_query_agents):
        """registerIP='any' is converted to '0.0.0.0' for the ip field type."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [{**AGENT_DOC_FULL, "registerIP": "any"}]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        assert docs[0]["wazuh"]["agent"]["register"]["ip"] == "0.0.0.0"

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_register_ip_real_value_preserved(self, mock_wazuh_db_query_agents):
        """A real IP for registerIP passes through unchanged."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [{**AGENT_DOC_FULL, "registerIP": "10.0.1.5"}]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        assert docs[0]["wazuh"]["agent"]["register"]["ip"] == "10.0.1.5"

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_register_ip_empty_field_omitted(self, mock_wazuh_db_query_agents):
        """An empty/missing registerIP does not produce an empty string in the output."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [{**AGENT_DOC_FULL, "registerIP": ""}]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        agent = docs[0].get("wazuh", {}).get("agent", {})
        assert agent.get("register") is None or "ip" not in agent.get("register", {})

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

        assert docs[0]["wazuh"]["agent"]["config"]["group"]["synced"] is True

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

        assert docs[0]["wazuh"]["agent"]["config"]["group"]["synced"] is False

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
        # Top-level keys must only be "@timestamp" and "wazuh" — no raw fields
        for dropped in (
            "manager",
            "node_name",
            "id",
            "name",
            "ip",
            "status",
            "group",
            "mergedSum",
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
            assert "wazuh" in doc
            assert "node" in doc["wazuh"]["cluster"]
            assert "name" in doc["wazuh"]["cluster"]

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
        assert doc["wazuh"]["cluster"]["node"] == "node01"
        assert doc["wazuh"]["cluster"]["name"] == "wazuh"

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
            assert "wazuh" in doc
            assert "node" in doc["wazuh"]["cluster"]
            assert "name" in doc["wazuh"]["cluster"]

    @pytest.mark.asyncio
    async def test_comms_metadata_values_match_server_config(self):
        """Comms metadata values are sourced from server.configuration."""
        tasks = _make_tasks(server=_make_server(node_name="node01"))
        local_result = _make_dapi_result([dict(REMOTED_STATS)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.get_daemons_stats",
            return_value=local_result,
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        doc = docs[0]
        assert doc["@timestamp"] == TIMESTAMP
        assert doc["wazuh"]["cluster"]["node"] == "node01"
        assert doc["wazuh"]["cluster"]["name"] == "wazuh"

    @pytest.mark.asyncio
    async def test_events_module_is_remoted_in_comms(self):
        """event.module is always set to 'remoted' in comms documents."""
        tasks = _make_tasks()
        local_result = _make_dapi_result([dict(REMOTED_STATS)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.get_daemons_stats",
            return_value=local_result,
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        assert docs[0]["event"]["module"] == "remoted"


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
    async def test_frequency_zero_no_side_effects(self):
        """NFR-2: frequency=0 exits cleanly — no errors, no warnings, no pending coroutines."""
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
            patch(
                "wazuh.core.indexer.metrics_snapshot.get_indexer_client",
                new_callable=AsyncMock,
            ) as mock_indexer,
        ):
            await tasks.run_metrics_snapshot()

        mock_sleep.assert_not_called()
        mock_collect.assert_not_called()
        mock_indexer.assert_not_called()
        tasks.logger.warning.assert_not_called()
        tasks.logger.error.assert_not_called()
        tasks.logger.exception.assert_not_called()

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

        agent = docs[0].get("wazuh", {}).get("agent", {})
        assert "disconnected_at" not in agent

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

        assert docs[0]["wazuh"]["agent"]["disconnected_at"] == 19345809

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

        active_doc = next(
            d for d in docs if d.get("wazuh", {}).get("agent", {}).get("id") == "001"
        )
        disconnected_doc = next(
            d for d in docs if d.get("wazuh", {}).get("agent", {}).get("id") == "002"
        )

        assert "disconnected_at" not in active_doc.get("wazuh", {}).get("agent", {})
        assert disconnected_doc["wazuh"]["agent"]["disconnected_at"] == 5000


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
                "wazuh": {"agent": {"id": "001"}},
                "@timestamp": TIMESTAMP,
            },
            {
                "wazuh": {"agent": {"id": "002"}},
                "@timestamp": TIMESTAMP,
            },
            {
                "wazuh": {"agent": {"id": "003"}},
                "@timestamp": TIMESTAMP,
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

        docs = [{"wazuh": {"agent": {"id": "001"}}}]
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
            {"wazuh": {"agent": {"id": "001"}}, "@timestamp": TIMESTAMP},
            {"wazuh": {"agent": {"id": "002"}}, "@timestamp": TIMESTAMP},
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
    tasks, mock_indexer, agent_docs=None, comms_docs=None, normalization_docs=None,
    collect_agents_override=None
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
            patch.object(
                tasks,
                "_collect_normalization_all_nodes",
                new_callable=AsyncMock,
                return_value=normalization_docs if normalization_docs is not None else [],
            ) as mock_norm,
            patch(
                "wazuh.core.indexer.metrics_snapshot.get_indexer_client",
                return_value=AsyncMock(
                    __aenter__=AsyncMock(return_value=mock_indexer),
                    __aexit__=AsyncMock(return_value=False),
                ),
            ),
        ):
            yield mock_agents, mock_comms, mock_norm

    return _ctx()


class TestCollectAndIndex:
    """Tests for MetricsSnapshotTasks._collect_and_index."""

    @pytest.mark.asyncio
    async def test_collects_agents_and_comms_then_bulk_indexes_both(self):
        """_collect_and_index calls both collectors and bulk-indexes their results."""
        agent_docs = [{"wazuh": {"agent": {"id": "001"}}, "@timestamp": TIMESTAMP}]
        comms_docs = [{"events": {"total": 1000}, "@timestamp": TIMESTAMP}]

        mock_indexer = AsyncMock()
        mock_indexer.metrics.bulk_index = AsyncMock()
        tasks = _make_tasks()

        with _patch_collect_and_index(tasks, mock_indexer, agent_docs, comms_docs) as (
            mock_agents,
            mock_comms,
            mock_norm,
        ):
            await tasks._collect_and_index()

        mock_agents.assert_awaited_once()
        mock_comms.assert_awaited_once()
        mock_norm.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_bulk_index_called_for_agents_index(self):
        """bulk_index is called with 'wazuh-metrics-agents' and the normalized agent docs."""
        agent_docs = [{"wazuh": {"agent": {"id": "001"}}}]

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
        comms_docs = [{"events": {"total": 1000}}]

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


# ---------------------------------------------------------------------------
# _build_jsonschema_properties
# ---------------------------------------------------------------------------


class TestBuildJsonschemaProperties:
    """Unit tests for the _build_jsonschema_properties helper."""

    def test_flat_properties_converted_to_jsonschema(self):
        """Top-level keyword fields are converted to anyOf JSON Schema."""
        props = {
            "field_a": {"type": "keyword"},
            "field_b": {"type": "integer"},
        }
        result = _build_jsonschema_properties(props)
        assert "field_a" in result
        assert result["field_a"] == {
            "anyOf": [
                {"type": "string"},
                {"type": "array", "items": {"type": "string"}},
            ]
        }
        assert "field_b" in result
        assert result["field_b"] == {
            "anyOf": [
                {"type": "integer"},
                {"type": "array", "items": {"type": "integer"}},
            ]
        }

    def test_nested_properties_produce_nested_schema(self):
        """Nested objects produce nested JSON Schema object definitions."""
        props = {
            "wazuh": {
                "properties": {
                    "agent": {
                        "properties": {
                            "id": {"type": "keyword"},
                        }
                    }
                }
            }
        }
        result = _build_jsonschema_properties(props)
        assert "wazuh" in result
        assert result["wazuh"]["type"] == "object"
        assert "agent" in result["wazuh"]["properties"]
        assert "id" in result["wazuh"]["properties"]["agent"]["properties"]
        assert result["wazuh"]["properties"]["agent"]["properties"]["id"] == {
            "anyOf": [
                {"type": "string"},
                {"type": "array", "items": {"type": "string"}},
            ]
        }

    def test_deep_nesting(self):
        """Three levels of nesting produce the correct nested schema."""
        props = {"a": {"properties": {"b": {"properties": {"c": {"type": "long"}}}}}}
        result = _build_jsonschema_properties(props)
        assert result["a"]["type"] == "object"
        assert result["a"]["properties"]["b"]["type"] == "object"
        assert result["a"]["properties"]["b"]["properties"]["c"] == {
            "anyOf": [
                {"type": "integer"},
                {"type": "array", "items": {"type": "integer"}},
            ]
        }

    def test_mixed_flat_and_nested(self):
        """Both flat and nested properties are included in the result."""
        props = {
            "@timestamp": {"type": "date"},
            "wazuh": {
                "properties": {
                    "cluster": {
                        "properties": {
                            "name": {"type": "keyword"},
                        }
                    }
                }
            },
        }
        result = _build_jsonschema_properties(props)
        assert "@timestamp" in result
        assert "wazuh" in result
        assert "cluster" in result["wazuh"]["properties"]
        assert "name" in result["wazuh"]["properties"]["cluster"]["properties"]

    def test_empty_properties(self):
        """An empty properties dict returns an empty dict."""
        assert _build_jsonschema_properties({}) == {}


# ---------------------------------------------------------------------------
# _opensearch_template_to_jsonschema
# ---------------------------------------------------------------------------


class TestOpensearchTemplateToJsonschema:
    """Unit tests for _opensearch_template_to_jsonschema."""

    def test_basic_conversion(self):
        """keyword fields under wazuh.agent produce correct nested JSON Schema."""
        schema = _opensearch_template_to_jsonschema(SAMPLE_TEMPLATE)
        assert schema["type"] == "object"
        assert "wazuh" in schema["properties"]
        agent_props = schema["properties"]["wazuh"]["properties"]["agent"]["properties"]
        assert "id" in agent_props
        assert agent_props["id"] == {
            "anyOf": [
                {"type": "string"},
                {"type": "array", "items": {"type": "string"}},
            ]
        }

    def test_integer_type_mapping(self):
        """integer OpenSearch type maps to JSON Schema integer under nested path."""
        schema = _opensearch_template_to_jsonschema(SAMPLE_TEMPLATE)
        agent_props = schema["properties"]["wazuh"]["properties"]["agent"]["properties"]
        assert agent_props["status_code"] == {
            "anyOf": [
                {"type": "integer"},
                {"type": "array", "items": {"type": "integer"}},
            ]
        }

    def test_strict_mode_sets_additional_properties_false(self):
        """dynamic=strict in the template sets additionalProperties: false."""
        schema = _opensearch_template_to_jsonschema(SAMPLE_TEMPLATE)
        assert schema.get("additionalProperties") is False

    def test_non_strict_mode_no_additional_properties_constraint(self):
        """dynamic!=strict does not set additionalProperties."""
        template = {
            "template": {
                "mappings": {
                    "dynamic": "true",
                    "properties": {"field": {"type": "keyword"}},
                }
            }
        }
        schema = _opensearch_template_to_jsonschema(template)
        assert "additionalProperties" not in schema

    def test_missing_template_key_returns_empty(self):
        """A template without the expected structure returns an empty dict."""
        assert _opensearch_template_to_jsonschema({}) == {}
        assert _opensearch_template_to_jsonschema({"template": {}}) == {}
        assert _opensearch_template_to_jsonschema({"template": {"mappings": {}}}) == {}

    def test_unknown_opensearch_type_becomes_empty_schema(self):
        """Unknown OpenSearch types map to an empty JSON Schema (any value allowed)."""
        template = {
            "template": {
                "mappings": {
                    "properties": {"field": {"type": "geo_point"}},
                }
            }
        }
        schema = _opensearch_template_to_jsonschema(template)
        assert schema["properties"]["field"] == {}

    def test_date_type_maps_to_string(self):
        """date OpenSearch type is represented as string in JSON Schema."""
        schema = _opensearch_template_to_jsonschema(SAMPLE_TEMPLATE)
        assert schema["properties"]["@timestamp"] == {
            "anyOf": [
                {"type": "string"},
                {"type": "array", "items": {"type": "string"}},
            ]
        }


# ---------------------------------------------------------------------------
# _load_schema
# ---------------------------------------------------------------------------


class TestLoadSchema:
    """Tests for MetricsSnapshotTasks._load_schema."""

    def test_missing_file_returns_none_and_logs_warning(self):
        """When the schema file does not exist, None is returned and a warning is logged."""
        tasks = _make_tasks()

        with patch(
            "wazuh.core.indexer.metrics_snapshot.os.path.isfile", return_value=False
        ):
            result = tasks._load_schema("metrics-agents.json")

        assert result is None
        tasks.logger.warning.assert_called()

    def test_missing_file_result_is_cached(self):
        """A None result from a missing file is cached so the filesystem is not re-checked."""
        tasks = _make_tasks()

        with patch(
            "wazuh.core.indexer.metrics_snapshot.os.path.isfile", return_value=False
        ) as mock_isfile:
            tasks._load_schema("metrics-agents.json")
            tasks._load_schema("metrics-agents.json")

        assert mock_isfile.call_count == 1

    def test_valid_schema_file_is_loaded_and_returned(self):
        """A valid schema file is loaded, converted, and returned as a dict."""
        tasks = _make_tasks()
        schema_content = json.dumps(SAMPLE_TEMPLATE)

        with (
            patch(
                "wazuh.core.indexer.metrics_snapshot.os.path.isfile", return_value=True
            ),
            patch("builtins.open", mock_open(read_data=schema_content)),
        ):
            result = tasks._load_schema("metrics-agents.json")

        assert result is not None
        assert result["type"] == "object"
        assert "wazuh" in result["properties"]

    def test_valid_schema_is_cached_after_first_load(self):
        """A successfully loaded schema is cached so the file is not re-opened."""
        tasks = _make_tasks()
        schema_content = json.dumps(SAMPLE_TEMPLATE)

        with (
            patch(
                "wazuh.core.indexer.metrics_snapshot.os.path.isfile", return_value=True
            ),
            patch("builtins.open", mock_open(read_data=schema_content)) as mock_file,
        ):
            tasks._load_schema("metrics-agents.json")
            tasks._load_schema("metrics-agents.json")

        assert mock_file.call_count == 1

    def test_invalid_json_returns_none_and_logs_exception(self):
        """A file with invalid JSON returns None and logs an exception."""
        tasks = _make_tasks()

        with (
            patch(
                "wazuh.core.indexer.metrics_snapshot.os.path.isfile", return_value=True
            ),
            patch("builtins.open", mock_open(read_data="not valid json {")),
        ):
            result = tasks._load_schema("metrics-agents.json")

        assert result is None
        tasks.logger.exception.assert_called()

    def test_template_without_mappings_returns_none_and_logs_warning(self):
        """A JSON file that does not contain mappings returns None with a warning."""
        tasks = _make_tasks()
        bad_template = json.dumps({"index_patterns": ["wazuh-metrics-agents*"]})

        with (
            patch(
                "wazuh.core.indexer.metrics_snapshot.os.path.isfile", return_value=True
            ),
            patch("builtins.open", mock_open(read_data=bad_template)),
        ):
            result = tasks._load_schema("metrics-agents.json")

        assert result is None
        tasks.logger.warning.assert_called()


# ---------------------------------------------------------------------------
# _validate_documents
# ---------------------------------------------------------------------------


class TestValidateDocuments:
    """Tests for MetricsSnapshotTasks._validate_documents."""

    def _make_flat_schema(self):
        """Return a minimal flat JSON Schema for testing validation logic."""
        return {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "@timestamp": {"type": "string"},
                "wazuh_cluster_node": {"type": "string"},
            },
            "additionalProperties": False,
        }

    def test_valid_document_is_kept(self):
        """A document conforming to the schema passes through unchanged."""
        tasks = _make_tasks()
        schema = self._make_flat_schema()
        docs = [{"id": "001", "@timestamp": TIMESTAMP, "wazuh_cluster_node": "n"}]

        result = tasks._validate_documents(docs, schema, "wazuh-metrics-agents")

        assert result == docs

    def test_invalid_document_is_filtered_and_logged(self):
        """A document that violates the schema is removed and an error is logged."""
        tasks = _make_tasks()
        schema = self._make_flat_schema()
        valid_doc = {"id": "001", "@timestamp": TIMESTAMP, "wazuh_cluster_node": "n"}
        invalid_doc = {
            "id": "002",
            "@timestamp": TIMESTAMP,
            "wazuh_cluster_node": "n",
            "unknown_field": "value",
        }

        result = tasks._validate_documents(
            [valid_doc, invalid_doc], schema, "wazuh-metrics-agents"
        )

        assert result == [valid_doc]
        tasks.logger.error.assert_called_once()

    def test_type_mismatch_triggers_validation_error(self):
        """A document with a wrong type for a field is filtered out."""
        tasks = _make_tasks()
        schema = self._make_flat_schema()
        bad_doc = {"id": 123, "@timestamp": TIMESTAMP, "wazuh_cluster_node": "n"}

        result = tasks._validate_documents([bad_doc], schema, "wazuh-metrics-agents")

        assert result == []
        tasks.logger.error.assert_called_once()

    def test_empty_document_list_returns_empty_list(self):
        """An empty input list returns an empty list without logging."""
        tasks = _make_tasks()
        schema = self._make_flat_schema()

        result = tasks._validate_documents([], schema, "wazuh-metrics-agents")

        assert result == []
        tasks.logger.error.assert_not_called()

    def test_multiple_invalid_documents_each_logged(self):
        """Each invalid document produces a separate error log entry."""
        tasks = _make_tasks()
        schema = self._make_flat_schema()
        docs = [
            {"id": 1, "@timestamp": TIMESTAMP, "wazuh_cluster_node": "n"},
            {"id": 2, "@timestamp": TIMESTAMP, "wazuh_cluster_node": "n"},
        ]

        result = tasks._validate_documents(docs, schema, "wazuh-metrics-agents")

        assert result == []
        assert tasks.logger.error.call_count == 2

    def test_all_valid_documents_are_returned(self):
        """When all documents are valid, the full list is returned."""
        tasks = _make_tasks()
        schema = {"type": "object", "properties": {"id": {"type": "string"}}}
        docs = [{"id": "001"}, {"id": "002"}, {"id": "003"}]

        result = tasks._validate_documents(docs, schema, "wazuh-metrics-agents")

        assert result == docs


# ---------------------------------------------------------------------------
# _collect_and_index with schema validation
# ---------------------------------------------------------------------------


class TestCollectAndIndexWithValidation:
    """Tests for schema validation integration in _collect_and_index."""

    @pytest.mark.asyncio
    async def test_no_schema_skips_validation_and_indexes_all(self):
        """When no schema is available, all documents are indexed without validation."""
        agent_docs = [{"id": "001"}, {"id": "002"}]
        comms_docs = [dict(REMOTED_STATS)]

        mock_indexer = AsyncMock()
        mock_indexer.metrics.bulk_index = AsyncMock()
        tasks = _make_tasks()

        with _patch_collect_and_index(tasks, mock_indexer, agent_docs, comms_docs):
            with patch.object(tasks, "_load_schema", return_value=None):
                with patch.object(tasks, "_validate_documents") as mock_validate:
                    await tasks._collect_and_index()

        mock_validate.assert_not_called()
        mock_indexer.metrics.bulk_index.assert_any_await(
            "wazuh-metrics-agents", agent_docs, tasks.bulk_size
        )

    @pytest.mark.asyncio
    async def test_with_schema_validates_agent_docs(self):
        """When agent schema is loaded, _validate_documents is called for agents."""
        agent_docs = [{"id": "001"}]
        comms_docs = []

        mock_indexer = AsyncMock()
        mock_indexer.metrics.bulk_index = AsyncMock()
        tasks = _make_tasks()

        fake_schema = {"type": "object", "properties": {"id": {"type": "string"}}}

        def _fake_load_schema(name):
            return fake_schema if "agents" in name else None

        with _patch_collect_and_index(tasks, mock_indexer, agent_docs, comms_docs):
            with patch.object(tasks, "_load_schema", side_effect=_fake_load_schema):
                with patch.object(
                    tasks, "_validate_documents", return_value=agent_docs
                ) as mock_validate:
                    await tasks._collect_and_index()

        mock_validate.assert_called_once_with(
            agent_docs, fake_schema, "wazuh-metrics-agents"
        )

    @pytest.mark.asyncio
    async def test_with_schema_validates_comms_docs(self):
        """When comms schema is loaded, _validate_documents is called for comms."""
        agent_docs = []
        comms_docs = [dict(REMOTED_STATS)]

        mock_indexer = AsyncMock()
        mock_indexer.metrics.bulk_index = AsyncMock()
        tasks = _make_tasks()

        fake_schema = {"type": "object"}

        def _fake_load_schema(name):
            return fake_schema if "comms" in name else None

        with _patch_collect_and_index(tasks, mock_indexer, agent_docs, comms_docs):
            with patch.object(tasks, "_load_schema", side_effect=_fake_load_schema):
                with patch.object(
                    tasks, "_validate_documents", return_value=comms_docs
                ) as mock_validate:
                    await tasks._collect_and_index()

        mock_validate.assert_called_once_with(
            comms_docs, fake_schema, "wazuh-metrics-comms"
        )

    @pytest.mark.asyncio
    async def test_invalid_docs_are_not_indexed(self):
        """Documents rejected by _validate_documents are not passed to bulk_index."""
        agent_docs = [{"id": "001"}, {"id": "002"}]
        valid_only = [{"id": "001"}]

        mock_indexer = AsyncMock()
        mock_indexer.metrics.bulk_index = AsyncMock()
        tasks = _make_tasks()

        fake_schema = {"type": "object"}

        with _patch_collect_and_index(tasks, mock_indexer, agent_docs, []):
            with patch.object(tasks, "_load_schema", return_value=fake_schema):
                with patch.object(
                    tasks, "_validate_documents", return_value=valid_only
                ):
                    await tasks._collect_and_index()

        mock_indexer.metrics.bulk_index.assert_any_await(
            "wazuh-metrics-agents", valid_only, tasks.bulk_size
        )


# ---------------------------------------------------------------------------
# _drop_none – empty dict removal (FR-1 fix)
# ---------------------------------------------------------------------------


class TestDropNone:
    """Tests for MetricsSnapshotTasks._drop_none — empty dict pruning."""

    def test_none_values_are_removed(self):
        """Simple None values at the top level are dropped."""
        result = MetricsSnapshotTasks._drop_none({"a": 1, "b": None})
        assert result == {"a": 1}

    def test_zero_integer_is_kept(self):
        """Zero integer values are NOT removed (only None is removed)."""
        result = MetricsSnapshotTasks._drop_none({"count": 0, "other": None})
        assert result == {"count": 0}

    def test_false_boolean_is_kept(self):
        """False boolean values are NOT removed."""
        result = MetricsSnapshotTasks._drop_none({"flag": False, "missing": None})
        assert result == {"flag": False}

    def test_empty_string_is_kept(self):
        """Empty string values are NOT removed (only None and {} are removed)."""
        result = MetricsSnapshotTasks._drop_none({"s": "", "missing": None})
        assert result == {"s": ""}

    def test_empty_dict_child_is_removed(self):
        """A nested dict that becomes empty after recursion is dropped from the parent."""
        result = MetricsSnapshotTasks._drop_none({"hash": {"md5": None}})
        assert result == {}

    def test_deeply_nested_empty_dict_is_removed(self):
        """Empty dicts are pruned at all levels of nesting."""
        result = MetricsSnapshotTasks._drop_none(
            {"config": {"hash": {"md5": None}, "version": "1.0"}}
        )
        assert result == {"config": {"version": "1.0"}}

    def test_non_empty_nested_dict_is_kept(self):
        """A nested dict with at least one non-None value is preserved."""
        result = MetricsSnapshotTasks._drop_none({"hash": {"md5": "abc123"}})
        assert result == {"hash": {"md5": "abc123"}}

    def test_mixed_top_level(self):
        """A realistic mixed document is cleaned correctly."""
        result = MetricsSnapshotTasks._drop_none(
            {
                "id": "001",
                "gone": None,
                "nested": {"kept": 42, "removed": None},
                "empty_subtree": {"a": None, "b": None},
            }
        )
        assert result == {
            "id": "001",
            "nested": {"kept": 42},
        }


# ---------------------------------------------------------------------------
# _normalize_agent_doc – no empty config.hash (FR-1 fix)
# ---------------------------------------------------------------------------


class TestNormalizeAgentDocNoEmptyHash:
    """config.hash must not appear when configSum is absent from the raw doc."""

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_config_hash_absent_when_configsum_missing(
        self, mock_wazuh_db_query_agents
    ):
        """wazuh.agent.config.hash is absent from the output when configSum is not in the raw doc."""
        # AGENT_DOC_FULL does not contain 'configSum', matching real v5.0 agent rows.
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [dict(AGENT_DOC_FULL)]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        agent_config = docs[0].get("wazuh", {}).get("agent", {}).get("config", {})
        assert "hash" not in agent_config, (
            "wazuh.agent.config.hash should be absent when configSum is not in the raw doc; "
            f"got: {agent_config.get('hash')}"
        )

    @pytest.mark.asyncio
    @patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
    async def test_config_hash_present_when_configsum_provided(
        self, mock_wazuh_db_query_agents
    ):
        """wazuh.agent.config.hash.md5 is present and correct when configSum IS supplied."""
        mock_wazuh_db_query_agents.return_value.run.return_value = {
            "items": [{**AGENT_DOC_FULL, "configSum": "deadbeef"}]
        }

        tasks = _make_tasks()
        docs = await tasks._collect_agents(TIMESTAMP)

        agent_config = docs[0]["wazuh"]["agent"]["config"]
        assert agent_config["hash"]["md5"] == "deadbeef"


# ---------------------------------------------------------------------------
# _normalize_comms_doc – zero value preservation (FR-2 fix)
# ---------------------------------------------------------------------------

# v5.0 remoted stats with every counter set to zero.
REMOTED_STATS_V5_ALL_ZEROS = {
    "metrics": {
        "bytes": {"sent": 0, "received": 0},
        "queues": {"received": {"usage": 0, "size": 0}},
        "messages": {
            "received_breakdown": {
                "event": 0,
                "discarded": 0,
                "dequeued_after": 0,
                "control": 0,
            }
        },
        "control_messages_queue_breakdown": {
            "inserted": 0,
            "replaced": 0,
            "processed": 0,
        },
        "tcp_sessions": 0,
        "control_messages_queue_usage": 0,
    }
}

# v5.0 remoted stats with every counter set to a non-zero value.
REMOTED_STATS_V5_NONZERO = {
    "metrics": {
        "bytes": {"sent": 512, "received": 256},
        "queues": {"received": {"usage": 10, "size": 100}},
        "messages": {
            "received_breakdown": {
                "event": 1000,
                "discarded": 3,
                "dequeued_after": 1,
                "control": 200,
            }
        },
        "control_messages_queue_breakdown": {
            "inserted": 210,
            "replaced": 8,
            "processed": 202,
        },
        "tcp_sessions": 5,
        "control_messages_queue_usage": 0.15,
    }
}


class TestNormalizeCommsDocZeroPreservation:
    """_normalize_comms_doc must preserve zero values from v5.0 nested stats format."""

    @pytest.mark.asyncio
    async def test_v5_zero_counters_are_present_in_output(self):
        """All zero-valued counters from a v5.0 doc appear in the normalized output."""
        tasks = _make_tasks()
        local_result = _make_dapi_result([dict(REMOTED_STATS_V5_ALL_ZEROS)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.get_daemons_stats",
            return_value=local_result,
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        assert len(docs) == 1
        doc = docs[0]
        flat_keys = _deep_keys(doc)
        for field in EXPECTED_COMMS_FIELDS:
            assert field in flat_keys, (
                f"Field '{field}' missing from normalized comms doc with all-zero v5.0 counters"
            )

    @pytest.mark.asyncio
    async def test_v5_zero_queue_size_is_present(self):
        """queue.size == 0 is preserved (not dropped) from a v5.0 doc."""
        tasks = _make_tasks()
        local_result = _make_dapi_result([dict(REMOTED_STATS_V5_ALL_ZEROS)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.get_daemons_stats",
            return_value=local_result,
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        assert docs[0]["queue"]["size"] == 0

    @pytest.mark.asyncio
    async def test_v5_zero_evt_count_is_present(self):
        """events.total == 0 is preserved (not dropped) from a v5.0 doc."""
        tasks = _make_tasks()
        local_result = _make_dapi_result([dict(REMOTED_STATS_V5_ALL_ZEROS)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.get_daemons_stats",
            return_value=local_result,
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        assert docs[0]["events"]["total"] == 0

    @pytest.mark.asyncio
    async def test_v5_zero_tcp_sessions_is_present(self):
        """tcp.sessions == 0 is preserved (not dropped) from a v5.0 doc."""
        tasks = _make_tasks()
        local_result = _make_dapi_result([dict(REMOTED_STATS_V5_ALL_ZEROS)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.get_daemons_stats",
            return_value=local_result,
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        assert docs[0]["tcp"]["sessions"] == 0

    @pytest.mark.asyncio
    async def test_v5_nonzero_counters_are_correct(self):
        """Non-zero v5.0 counters are mapped to the correct normalized fields."""
        tasks = _make_tasks()
        local_result = _make_dapi_result([dict(REMOTED_STATS_V5_NONZERO)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.get_daemons_stats",
            return_value=local_result,
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        doc = docs[0]
        assert doc["queue"]["size"] == 10
        assert doc["queue"]["capacity"] == 100
        assert doc["tcp"]["sessions"] == 5
        assert doc["events"]["total"] == 1000
        assert doc["discarded"]["total"] == 3
        assert doc["network"]["egress"]["bytes"] == 512
        assert doc["network"]["ingress"]["bytes"] == 256
        assert doc["messages"]["total"] == 200
        assert doc["messages"]["control"]["usage"] == 0.15
        assert doc["messages"]["control"]["received"]["total"] == 210
        assert doc["messages"]["control"]["replaced"]["total"] == 8
        assert doc["messages"]["control"]["processed"]["total"] == 202
        assert doc["messages"]["control"]["dropped_on_close"]["total"] == 1

    @pytest.mark.asyncio
    async def test_legacy_flat_format_still_works(self):
        """Legacy flat-format stats (pre-v5.0) continue to produce correct output."""
        tasks = _make_tasks()
        local_result = _make_dapi_result([dict(REMOTED_STATS)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.get_daemons_stats",
            return_value=local_result,
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        doc = docs[0]
        flat_keys = _deep_keys(doc)
        for field in EXPECTED_COMMS_FIELDS:
            assert field in flat_keys, f"Legacy field '{field}' missing"

        assert doc["queue"]["size"] == 10
        assert doc["events"]["total"] == 1000
        assert doc["tcp"]["sessions"] == 5


# ---------------------------------------------------------------------------
# Engine metrics normalization tests
# ---------------------------------------------------------------------------

ENGINE_DUMP_RESPONSE = {
    "status": 0,
    "name": "engine",
    "uptime": 99000,
    "global": [
        {"name": "router.queue.size", "type": 0, "enabled": True, "value": 1000},
        {"name": "router.queue.usage.percent", "type": 1, "enabled": True, "value": 55.5},
        {"name": "router.eps.1m", "type": 1, "enabled": True, "value": 250.0},
        {"name": "router.eps.5m", "type": 1, "enabled": True, "value": 240.0},
        {"name": "router.eps.30m", "type": 1, "enabled": True, "value": 230.0},
        {"name": "router.events.processed", "type": 0, "enabled": True, "value": 100000},
        {"name": "router.events.dropped", "type": 0, "enabled": True, "value": 5},
        {"name": "indexer.queue.size", "type": 0, "enabled": True, "value": 200},
        {"name": "indexer.queue.usage.percent", "type": 1, "enabled": True, "value": 20.0},
        {"name": "indexer.events.dropped", "type": 0, "enabled": True, "value": 0},
        {"name": "server.bytes.received", "type": 0, "enabled": True, "value": 1048576},
        {"name": "server.events.received", "type": 0, "enabled": True, "value": 100005},
    ],
    "spaces": [
        {
            "name": "default",
            "metrics": [
                {"name": "space.default.events.unclassified", "type": 0, "enabled": True, "value": 10},
                {"name": "space.default.events.discarded", "type": 0, "enabled": True, "value": 2},
                {"name": "space.default.events.discarded.prefilter", "type": 0, "enabled": True, "value": 1},
                {"name": "space.default.events.discarded.postfilter", "type": 0, "enabled": True, "value": 1},
            ],
        }
    ],
}


class TestNormalizeNormalizationDoc:
    def _base_doc(self):
        doc = dict(ENGINE_DUMP_RESPONSE)
        doc["@timestamp"] = TIMESTAMP
        doc["wazuh.cluster.node"] = "node01"
        doc["wazuh.cluster.name"] = "wazuh"
        return doc

    def test_top_level_metadata(self):
        doc = MetricsSnapshotTasks._normalize_normalization_doc(self._base_doc())
        assert doc["@timestamp"] == TIMESTAMP
        assert doc["wazuh"]["cluster"]["node"] == "node01"
        assert doc["wazuh"]["cluster"]["name"] == "wazuh"
        assert doc["wazuh"]["schema"]["version"] == "1"
        assert doc["event"]["module"] == "engine"

    def test_engine_fields(self):
        doc = MetricsSnapshotTasks._normalize_normalization_doc(self._base_doc())
        assert doc["engine"]["name"] == "engine"
        assert doc["engine"]["uptime"] == 99000

    def test_router_metrics(self):
        doc = MetricsSnapshotTasks._normalize_normalization_doc(self._base_doc())
        assert doc["router"]["queue"]["size"] == 1000
        assert doc["router"]["queue"]["usage"]["percent"] == 55.5
        assert doc["router"]["eps"]["1m"] == 250.0
        assert doc["router"]["eps"]["5m"] == 240.0
        assert doc["router"]["eps"]["30m"] == 230.0
        assert doc["router"]["events"]["processed"] == 100000
        assert doc["router"]["events"]["dropped"] == 5

    def test_indexer_metrics(self):
        doc = MetricsSnapshotTasks._normalize_normalization_doc(self._base_doc())
        assert doc["indexer"]["queue"]["size"] == 200
        assert doc["indexer"]["queue"]["usage"]["percent"] == 20.0
        assert doc["indexer"]["events"]["dropped"] == 0

    def test_server_metrics(self):
        doc = MetricsSnapshotTasks._normalize_normalization_doc(self._base_doc())
        assert doc["server"]["bytes"]["received"] == 1048576
        assert doc["server"]["events"]["received"] == 100005

    def test_spaces_mapping(self):
        doc = MetricsSnapshotTasks._normalize_normalization_doc(self._base_doc())
        assert len(doc["spaces"]) == 1
        space = doc["spaces"][0]
        assert space["name"] == "default"
        assert space["events"]["unclassified"] == 10
        assert space["events"]["discarded"] == 2
        assert space["events"]["discarded_prefilter"] == 1
        assert space["events"]["discarded_postfilter"] == 1

    def test_empty_global_drops_metric_fields(self):
        doc = dict(ENGINE_DUMP_RESPONSE)
        doc["global"] = []
        doc["spaces"] = []
        doc["@timestamp"] = TIMESTAMP
        doc["wazuh.cluster.node"] = "node01"
        doc["wazuh.cluster.name"] = "wazuh"
        result = MetricsSnapshotTasks._normalize_normalization_doc(doc)
        assert "router" not in result
        assert "indexer" not in result
        assert "server" not in result
        assert "spaces" not in result

    def test_zero_value_preserved(self):
        doc = dict(ENGINE_DUMP_RESPONSE)
        doc["global"] = [{"name": "router.events.dropped", "type": 0, "enabled": True, "value": 0}]
        doc["spaces"] = []
        doc["@timestamp"] = TIMESTAMP
        doc["wazuh.cluster.node"] = "node01"
        doc["wazuh.cluster.name"] = "wazuh"
        result = MetricsSnapshotTasks._normalize_normalization_doc(doc)
        assert result["router"]["events"]["dropped"] == 0


class TestCollectNormalizationAllNodes:
    @pytest.mark.asyncio
    async def test_local_node_collected(self):
        tasks = _make_tasks()
        engine_result = _make_dapi_result([dict(ENGINE_DUMP_RESPONSE)])

        with patch(
            "wazuh.core.indexer.metrics_snapshot.get_engine_metrics",
            return_value=engine_result,
        ):
            docs = await tasks._collect_normalization_all_nodes(TIMESTAMP)

        assert len(docs) == 1
        assert docs[0]["@timestamp"] == TIMESTAMP
        assert docs[0]["wazuh"]["cluster"]["node"] == "node01"
        assert docs[0]["engine"]["name"] == "engine"

    @pytest.mark.asyncio
    async def test_worker_node_uses_dapi(self):
        server = _make_server(workers={"worker01": MagicMock()})
        tasks = _make_tasks(server=server)
        master_result = _make_dapi_result([dict(ENGINE_DUMP_RESPONSE)])
        worker_result = _make_dapi_result([dict(ENGINE_DUMP_RESPONSE)])
        dapi_mock = AsyncMock(return_value=worker_result)

        with patch(
            "wazuh.core.indexer.metrics_snapshot.get_engine_metrics",
            return_value=master_result,
        ), patch(
            "wazuh.core.indexer.metrics_snapshot.DistributedAPI",
        ) as mock_dapi_cls:
            mock_dapi_cls.return_value.distribute_function = dapi_mock
            docs = await tasks._collect_normalization_all_nodes(TIMESTAMP)

        assert len(docs) == 2
        assert mock_dapi_cls.called

    @pytest.mark.asyncio
    async def test_node_failure_skipped(self):
        tasks = _make_tasks()

        with patch(
            "wazuh.core.indexer.metrics_snapshot.get_engine_metrics",
            side_effect=Exception("socket error"),
        ):
            docs = await tasks._collect_normalization_all_nodes(TIMESTAMP)

        assert docs == []
