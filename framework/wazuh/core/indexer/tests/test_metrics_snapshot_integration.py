# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
Integration and regression tests for the manager metrics snapshot indexing pipeline.

Integration tests require a local OpenSearch instance. They are skipped automatically
when OpenSearch is not reachable at OPENSEARCH_URL.

Regression tests run fully isolated (no live dependency required).
"""

import sys
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import requests

# ---------------------------------------------------------------------------
# Optional OpenSearch availability check
# ---------------------------------------------------------------------------

OPENSEARCH_URL = "http://localhost:9200"
OPENSEARCH_AVAILABLE = False

try:
    resp = requests.get(OPENSEARCH_URL, timeout=3)
    OPENSEARCH_AVAILABLE = resp.status_code == 200
except Exception:
    pass

requires_opensearch = pytest.mark.skipif(
    not OPENSEARCH_AVAILABLE,
    reason="OpenSearch not reachable at localhost:9200 — skipping integration tests",
)

# ---------------------------------------------------------------------------
# Module mocking (same pattern as existing unit tests)
# ---------------------------------------------------------------------------

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

import wazuh.core.indexer as _indexer_pkg
_indexer_pkg.metrics_snapshot = _metrics_snapshot_module

# ---------------------------------------------------------------------------
# Shared fixtures and constants
# ---------------------------------------------------------------------------

CLUSTER_ITEMS = {
    "intervals": {"master": {"metrics_frequency": 600, "metrics_bulk_size": 100}}
}

# Values correspond to normalized fields (ECS mapping)
AGENT_DOCS = [
    {
        "wazuh.agent.id": "001",
        "wazuh.agent.name": "ubuntu-agent",
        "wazuh.agent.host.ip": "10.0.0.1",
        "wazuh.agent.status": "active",
        "wazuh.agent.version": "Wazuh v5.0.0",
        "wazuh.agent.groups": ["default"],
        "wazuh.agent.config.group.hash.md5": "def456",
        "wazuh.agent.registered_at": "2026-01-01T00:00:00Z",
        "wazuh.agent.last_seen": "2026-03-19T10:00:00Z",
        "wazuh.agent.disconnected_at": 0,
        "wazuh.agent.register.ip": "0.0.0.0/0",
        "wazuh.agent.config.group.synced": True,
        "wazuh.agent.status_code": 0,
        "wazuh.agent.host.os.name": "Ubuntu",
        "wazuh.agent.host.os.version": "22.04",
        "wazuh.agent.host.os.platform": "ubuntu",
        "wazuh.agent.host.architecture": "x86_64",
    }
]

# Values correspond to normalized fields (ECS mapping)
COMMS_DOCS = [
    {
        "queue.usage": 10,
        "queue.capacity": 100,
        "tcp.sessions": 5,
        "events.total": 1000,
        "messages.control.received.total": 200,
        "discarded.total": 3,
        "network.egress.bytes": 512000,
        "network.ingress.bytes": 256000,
        "messages.control.dropped_on_close.total": 1,
        "messages.control.usage": 0.15,
        "messages.control.replaced.total": 8,
        "messages.control.processed.total": 202,
        "events.module": "remoted",
    }
]

TIMESTAMP = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_server(node_name="master-node"):
    server = MagicMock()
    server.configuration = {
        "node_name": node_name,
        "name": "wazuh-cluster",
    }
    server.clients = {}
    server.setup_task_logger.return_value = MagicMock()
    return server


def _make_tasks(server=None):
    if server is None:
        server = _make_server()
    return MetricsSnapshotTasks(server=server, cluster_items=CLUSTER_ITEMS)


# ---------------------------------------------------------------------------
# Integration tests — require live OpenSearch
# ---------------------------------------------------------------------------


class TestBulkIndexingIntegration:
    """End-to-end bulk indexing tests against a local OpenSearch instance."""

    @pytest.fixture
    async def os_client(self):
        """Fixture providing an OpenSearch client, handling teardown/cleanup of indices."""
        pytest.importorskip("opensearchpy")
        from opensearchpy import AsyncOpenSearch

        client = AsyncOpenSearch(
            hosts=[{"host": "localhost", "port": 9200}],
            use_ssl=False,
            verify_certs=False,
        )
        yield client

        # Teardown: Clean up indices created during tests to avoid cross-run interference
        try:
            await client.indices.delete(index="wazuh-metrics-agents-test", ignore_unavailable=True)
            await client.indices.delete(index="wazuh-metrics-comms-test", ignore_unavailable=True)
        except Exception:
            pass
        finally:
            await client.close()

    @requires_opensearch
    @pytest.mark.asyncio
    async def test_agents_documents_indexed_successfully(self, os_client):
        """Bulk indexing of agent docs produces at least one document in the data stream."""
        from opensearchpy.helpers import async_bulk

        index = "wazuh-metrics-agents-test"
        docs_with_meta = [
            {
                "@timestamp": TIMESTAMP,
                "wazuh.cluster.node": "master-node",
                "wazuh.cluster.name": "wazuh-cluster",
                "wazuh.schema.version": "1",
                **doc,
            }
            for doc in AGENT_DOCS
        ]

        actions = [
            {"_op_type": "index", "_index": index, "_source": doc}
            for doc in docs_with_meta
        ]

        success, failed = await async_bulk(os_client, actions, raise_on_error=False)

        assert success >= 1
        assert failed == []

    @requires_opensearch
    @pytest.mark.asyncio
    async def test_agents_documents_have_timestamp(self, os_client):
        """Documents indexed into wazuh-metrics-agents contain a valid @timestamp."""
        from opensearchpy.helpers import async_bulk

        index = "wazuh-metrics-agents-test"
        doc = {"@timestamp": TIMESTAMP, "wazuh.agent.id": "001", "wazuh.agent.name": "test-agent"}
        actions = [{"_op_type": "index", "_index": index, "_source": doc}]

        await async_bulk(os_client, actions, raise_on_error=False)

        # Refresh and verify
        await os_client.indices.refresh(index=index)
        result = await os_client.search(
            index=index,
            body={"query": {"term": {"wazuh.agent.id.keyword": "001"}}},
        )

        hits = result["hits"]["hits"]
        assert len(hits) >= 1
        source = hits[0]["_source"]
        assert "@timestamp" in source

        # Verify ISO 8601 format
        ts = source["@timestamp"]
        datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")

    @requires_opensearch
    @pytest.mark.asyncio
    async def test_comms_documents_indexed_successfully(self, os_client):
        """Bulk indexing of comms docs produces at least one document in the data stream."""
        from opensearchpy.helpers import async_bulk

        index = "wazuh-metrics-comms-test"
        docs_with_meta = [
            {
                "@timestamp": TIMESTAMP,
                "wazuh.cluster.node": "master-node",
                "wazuh.cluster.name": "wazuh-cluster",
                "wazuh.schema.version": "1",
                **doc,
            }
            for doc in COMMS_DOCS
        ]

        actions = [
            {"_op_type": "index", "_index": index, "_source": doc}
            for doc in docs_with_meta
        ]

        success, failed = await async_bulk(os_client, actions, raise_on_error=False)

        assert success >= 1
        assert failed == []

    @requires_opensearch
    @pytest.mark.asyncio
    async def test_comms_documents_have_expected_fields(self, os_client):
        """Documents indexed into wazuh-metrics-comms contain all expected fields."""
        from opensearchpy.helpers import async_bulk

        index = "wazuh-metrics-comms-test"
        doc = {
            "@timestamp": TIMESTAMP,
            "wazuh.cluster.node": "master-node",
            "wazuh.cluster.name": "wazuh-cluster",
            "wazuh.schema.version": "1",
            **COMMS_DOCS[0],
        }
        actions = [{"_op_type": "index", "_index": index, "_source": doc}]
        await async_bulk(os_client, actions, raise_on_error=False)
        await os_client.indices.refresh(index=index)

        result = await os_client.search(
            index=index,
            body={"query": {"term": {"queue.usage": 10}}},
            size=1,
        )

        hits = result["hits"]["hits"]
        assert len(hits) >= 1
        source = hits[0]["_source"]

        expected_fields = [
            "@timestamp",
            "wazuh.cluster.node",
            "wazuh.cluster.name",
            "wazuh.schema.version",
            "queue.usage",
            "queue.capacity",
            "tcp.sessions",
            "events.total",
            "network.egress.bytes",
            "network.ingress.bytes",
        ]
        for field in expected_fields:
            assert field in source, f"Missing field: {field}"

    @requires_opensearch
    @pytest.mark.asyncio
    async def test_timestamp_format_is_iso8601(self, os_client):
        """@timestamp is present and correctly formatted in all indexed documents."""
        from opensearchpy.helpers import async_bulk

        for index in ["wazuh-metrics-agents-test", "wazuh-metrics-comms-test"]:
            doc = {"@timestamp": TIMESTAMP, "test_field": "value"}
            actions = [{"_op_type": "index", "_index": index, "_source": doc}]
            await async_bulk(os_client, actions, raise_on_error=False)
            await os_client.indices.refresh(index=index)

            result = await os_client.search(
                index=index,
                body={"query": {"exists": {"field": "@timestamp"}}},
                size=1,
            )
            hits = result["hits"]["hits"]
            assert len(hits) >= 1
            ts = hits[0]["_source"]["@timestamp"]
            # Must parse as ISO 8601
            datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Regression tests — fully isolated, no live dependency
# ---------------------------------------------------------------------------


class TestRegressionDaemonStats:
    """
    Regression tests: MetricsSnapshotTasks registration must not alter
    the GET /manager/daemons/stats response shape.
    """

    @pytest.mark.asyncio
    async def test_get_daemons_stats_still_callable(self):
        """get_daemons_stats remains callable after MetricsSnapshotTasks is instantiated."""
        mock_get_daemons_stats = MagicMock(return_value={"data": {"affected_items": []}})

        with patch("wazuh.core.indexer.metrics_snapshot.get_daemons_stats", mock_get_daemons_stats):
            tasks = _make_tasks()

        # Instantiating MetricsSnapshotTasks must not call get_daemons_stats
        mock_get_daemons_stats.assert_not_called()

    @pytest.mark.asyncio
    async def test_metrics_task_does_not_modify_daemons_stats_response(self):
        """_collect_comms_all_nodes does not mutate the DAPI result object."""
        tasks = _make_tasks()

        original_stats = dict(COMMS_DOCS[0])
        dapi_result = MagicMock()
        dapi_result.affected_items = [dict(original_stats)]

        with patch(
            "wazuh.core.indexer.metrics_snapshot.DistributedAPI",
            return_value=AsyncMock(
                distribute_function=AsyncMock(return_value=dapi_result)
            ),
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        # Original affected_items should be unmodified
        assert dapi_result.affected_items[0] == original_stats

    @pytest.mark.asyncio
    async def test_collect_comms_does_not_raise_on_empty_cluster(self):
        """_collect_comms_all_nodes completes without error when no workers exist."""
        tasks = _make_tasks(server=_make_server())

        dapi_result = MagicMock()
        dapi_result.affected_items = []

        with patch(
            "wazuh.core.indexer.metrics_snapshot.DistributedAPI",
            return_value=AsyncMock(
                distribute_function=AsyncMock(return_value=dapi_result)
            ),
        ):
            docs = await tasks._collect_comms_all_nodes(TIMESTAMP)

        assert docs == []


def _mock_wdb_http_client(agents_data):
    """Build a patchable stand-in for ``get_wdb_http_client()``.

    ``get_wdb_http_client`` is an ``@asynccontextmanager`` function: calling it returns an
    async context manager, and ``async with ... as wdb_client`` yields the client. Returns the
    (context_manager, client) pair so a test can both patch the former and assert on the latter.
    """
    client = AsyncMock()
    client.get_all_agents = AsyncMock(return_value=agents_data)

    # MagicMock() auto-provisions __aenter__/__aexit__ as async-aware magic methods; configure
    # their return values rather than replacing the attributes outright -- `async with` resolves
    # dunders on the type, not the instance, so a wholesale reassignment is silently never called.
    context_manager = MagicMock()
    context_manager.__aenter__.return_value = client
    context_manager.__aexit__.return_value = None

    return context_manager, client


class TestRegressionAgentsEndpoint:
    """
    Regression tests: MetricsSnapshotTasks registration must not alter
    the GET /agents response shape.

    _collect_agents fetches agents via the wdb-http `/agents/all` endpoint
    (WazuhDBHTTPClient.get_all_agents), not WazuhDBQueryAgents — see
    metrics_snapshot.py's _collect_agents and wdb_http.py's get_wdb_http_client.
    """

    @pytest.mark.asyncio
    async def test_get_all_agents_called_through_wdb_http_client(self):
        """_collect_agents fetches every agent through get_wdb_http_client().get_all_agents()."""
        context_manager, client = _mock_wdb_http_client([])

        with patch("wazuh.core.indexer.metrics_snapshot.get_wdb_http_client", return_value=context_manager):
            tasks = _make_tasks()
            await tasks._collect_agents(TIMESTAMP)

        client.get_all_agents.assert_awaited_once_with()

    @pytest.mark.asyncio
    async def test_collect_agents_adds_metadata_fields(self):
        """_collect_agents correctly maps fields into the nested ECS structure and adds metadata."""
        # Shape returned by the real /agents/all endpoint: raw int id, flat os.* fields.
        original_agent = {"id": 1, "name": "test-agent", "status": "active"}
        context_manager, _ = _mock_wdb_http_client([dict(original_agent)])

        with patch("wazuh.core.indexer.metrics_snapshot.get_wdb_http_client", return_value=context_manager):
            tasks = _make_tasks()
            docs = await tasks._collect_agents(TIMESTAMP)

        assert len(docs) == 1
        doc = docs[0]

        # Zero-padded to 3 digits, like everywhere else agent ids are indexed.
        assert doc["wazuh"]["agent"]["id"] == "001"
        assert doc["wazuh"]["agent"]["name"] == original_agent["name"]
        assert doc["wazuh"]["agent"]["status"] == original_agent["status"]

        assert "@timestamp" in doc
        assert doc["wazuh"]["cluster"]["node"] == "master-node"
        assert doc["wazuh"]["cluster"]["name"] == "wazuh-cluster"
        assert doc["wazuh"]["schema"]["version"] == "1"

    @pytest.mark.asyncio
    async def test_collect_agents_returns_list(self):
        """_collect_agents always returns a list, never None."""
        context_manager, _ = _mock_wdb_http_client([])

        with patch("wazuh.core.indexer.metrics_snapshot.get_wdb_http_client", return_value=context_manager):
            tasks = _make_tasks()
            result = await tasks._collect_agents(TIMESTAMP)

        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_metrics_task_registration_does_not_interfere_with_agents_query(self):
        """Instantiating MetricsSnapshotTasks does not trigger any agent query."""
        context_manager, client = _mock_wdb_http_client([])

        with patch("wazuh.core.indexer.metrics_snapshot.get_wdb_http_client", return_value=context_manager):
            _make_tasks()

        client.get_all_agents.assert_not_awaited()
