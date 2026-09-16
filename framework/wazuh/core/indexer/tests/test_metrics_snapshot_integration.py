# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
Integration and regression tests for the manager metrics snapshot indexing pipeline.

Integration tests require a real OpenSearch instance reachable with the credentials the
manager itself would use (TLS + basic auth, matching indexer.ssl in wazuh-manager.conf;
plain HTTP OpenSearch is not a config this pipeline ever runs against). They write into the
real wazuh-metrics-* data streams, so they only run when OPENSEARCH_URL is set explicitly;
with it unset they are skipped, whatever is listening on localhost. Configure via:

    OPENSEARCH_URL        e.g. https://localhost:9200 (no default: opt-in)
    OPENSEARCH_USER       default admin
    OPENSEARCH_PASSWORD   default admin
    OPENSEARCH_VERIFY_CERTS  "1" to verify TLS certs (default: unverified, devcontainer
                              self-signed setup)

Regression tests run fully isolated (no live dependency required).
"""

import os
import sys
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Optional OpenSearch availability check
# ---------------------------------------------------------------------------

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL")
OPENSEARCH_USER = os.environ.get("OPENSEARCH_USER", "admin")
OPENSEARCH_PASSWORD = os.environ.get("OPENSEARCH_PASSWORD", "admin")
OPENSEARCH_VERIFY_CERTS = os.environ.get("OPENSEARCH_VERIFY_CERTS", "") == "1"
OPENSEARCH_AVAILABLE = False

if OPENSEARCH_URL:
    try:
        resp = requests.get(
            OPENSEARCH_URL,
            auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
            verify=OPENSEARCH_VERIFY_CERTS,
            timeout=3,
        )
        OPENSEARCH_AVAILABLE = resp.status_code == 200
    except Exception:
        pass

# Real index templates, as downloaded by `make deps` into src/external/indexer-plugins
# (see src/Makefile's INDEXER_PLUGINS_DIR) and installed under etc/indexer-plugins/ on a
# real manager. Used to exercise the same schema validation _load_schema() runs in
# production, not a stand-in.
INDEXER_TEMPLATES_PATH = os.environ.get(
    "INDEXER_TEMPLATES_PATH", "src/external/indexer-plugins"
)
INDEXER_TEMPLATES_AVAILABLE = all(
    os.path.isfile(os.path.join(INDEXER_TEMPLATES_PATH, name))
    for name in ("metrics-agents.json", "metrics-comms.json", "metrics-normalization.json")
)
requires_indexer_templates = pytest.mark.skipif(
    not INDEXER_TEMPLATES_AVAILABLE,
    reason=(
        f"Real index templates not found under {INDEXER_TEMPLATES_PATH} — run `make deps` "
        "or set INDEXER_TEMPLATES_PATH, otherwise schema validation is not exercised"
    ),
)

requires_opensearch = pytest.mark.skipif(
    not OPENSEARCH_AVAILABLE,
    reason=(
        f"OpenSearch not reachable at {OPENSEARCH_URL} — skipping integration tests"
        if OPENSEARCH_URL
        else "OPENSEARCH_URL not set — integration tests write into the real metrics "
        "data streams and only run on explicit opt-in"
    ),
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
    "wazuh.core.cluster.control": MagicMock(),
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

# patch.dict restores sys.modules to its pre-`with` snapshot on exit, which silently
# drops the 'wazuh.core.indexer.metrics_snapshot' entry the import above just created
# (it wasn't a pre-existing key). Without putting it back, any later
# patch("wazuh.core.indexer.metrics_snapshot.<name>", ...) re-imports the module for
# real (this time with no mocked dependencies) and patches that unrelated copy instead
# of the one MetricsSnapshotTasks is actually bound to — the patch silently no-ops.
sys.modules["wazuh.core.indexer.metrics_snapshot"] = _metrics_snapshot_module

import wazuh.core.indexer as _indexer_pkg
from wazuh.core.indexer.metrics import MetricsIndex

_indexer_pkg.metrics_snapshot = _metrics_snapshot_module

# ---------------------------------------------------------------------------
# Shared fixtures and constants
# ---------------------------------------------------------------------------

CLUSTER_ITEMS = {
    "intervals": {"master": {"metrics_frequency": 600, "metrics_bulk_size": 100}}
}

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


class TestMetricsPipelineIntegration:
    """Runs MetricsSnapshotTasks._collect_and_index() end to end against a real
    indexer and confirms documents land in the three *real* data streams
    (wazuh-metrics-agents, wazuh-metrics-comms-v4, wazuh-metrics-normalization) with
    the shape their index templates expect — not an ad-hoc scratch index, which is
    what let a real template mismatch (issue #39283) pass unnoticed here before.

    Collection (_collect_agents / _collect_comms_all_nodes /
    _collect_normalization_all_nodes) is mocked — this test's job is the last mile:
    normalization, schema validation against the real downloaded templates (skipped,
    not silently bypassed, when they are not present — see requires_indexer_templates)
    and bulk-index against a live indexer, tagged under a unique node name so it never
    collides with a real cluster node and is cleaned up afterwards.
    """

    NODE_NAME = f"itest-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    async def indexer_client(self):
        """Real AsyncOpenSearch client, using the same TLS/auth shape the manager
        itself connects with (see the module docstring for the env vars)."""
        pytest.importorskip("opensearchpy")
        from opensearchpy import AsyncOpenSearch

        client = AsyncOpenSearch(
            hosts=[OPENSEARCH_URL],
            http_auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
            use_ssl=OPENSEARCH_URL.startswith("https"),
            verify_certs=OPENSEARCH_VERIFY_CERTS,
        )
        yield client

        # Teardown: remove only this run's own documents, never a broad delete. Each
        # index is cleaned up independently — one failing must not skip the other two.
        # The refresh makes documents written moments ago visible to delete_by_query,
        # which otherwise misses them when the test failed before its own refresh.
        cleanup_errors = []
        for index in (
            "wazuh-metrics-agents",
            "wazuh-metrics-comms-v4",
            "wazuh-metrics-normalization",
        ):
            try:
                await client.indices.refresh(index=index, ignore_unavailable=True)
                await client.delete_by_query(
                    index=index,
                    body={"query": {"term": {"wazuh.cluster.node": self.NODE_NAME}}},
                    ignore_unavailable=True,
                    conflicts="proceed",
                )
            except Exception as exc:
                cleanup_errors.append(f"{index}: {exc}")
        await client.close()
        if cleanup_errors:
            # Loud on purpose: these are the real data streams the environment's own
            # metrics live in, so leftover synthetic documents must not go unnoticed.
            pytest.fail(
                f"could not clean up documents tagged {self.NODE_NAME}: "
                + "; ".join(cleanup_errors)
            )

    @staticmethod
    def _patch_real_indexer_client(client):
        """Make _collect_and_index()'s `async with get_indexer_client()` yield a real
        MetricsIndex backed by `client`, bypassing the manager's own config/keystore-
        driven connection setup (covered separately by test_indexer.py)."""
        handle = SimpleNamespace(metrics=MetricsIndex(client))
        return patch(
            "wazuh.core.indexer.metrics_snapshot.get_indexer_client",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=handle),
                __aexit__=AsyncMock(return_value=False),
            ),
        )

    @requires_opensearch
    @requires_indexer_templates
    @pytest.mark.asyncio
    async def test_pipeline_indexes_documents_into_the_three_real_data_streams(
        self, indexer_client
    ):
        server = _make_server(node_name=self.NODE_NAME)
        tasks = _make_tasks(server=server)
        tasks.logger = MagicMock()

        agent_doc = tasks._normalize_agent_doc(
            {
                "id": "999",
                "name": "itest-agent",
                "status": "active",
                "status_code": 0,
                "version": "v5.0.0",
                "os.name": "Ubuntu",
                "os.platform": "ubuntu",
                "os.version": "22.04",
                "@timestamp": TIMESTAMP,
                "wazuh.cluster.node": self.NODE_NAME,
                "wazuh.cluster.name": "wazuh-cluster",
            }
        )
        comms_doc = tasks._normalize_comms_doc(
            {
                "@timestamp": TIMESTAMP,
                "wazuh.cluster.node": self.NODE_NAME,
                "wazuh.cluster.name": "wazuh-cluster",
                "metrics": {"bytes": {"sent": 1, "received": 1}, "tcp_sessions": 1},
            }
        )
        normalization_doc = tasks._normalize_normalization_doc(
            {"name": "itest.metric", "type": "counter", "enabled": True, "value": 1},
            None,
            TIMESTAMP,
            "wazuh-cluster",
            self.NODE_NAME,
        )

        with (
            patch.object(
                tasks, "_collect_agents", new_callable=AsyncMock, return_value=[agent_doc]
            ),
            patch.object(
                tasks,
                "_collect_comms_all_nodes",
                new_callable=AsyncMock,
                return_value=[comms_doc],
            ),
            patch.object(
                tasks,
                "_collect_normalization_all_nodes",
                new_callable=AsyncMock,
                return_value=[normalization_doc],
            ),
            self._patch_real_indexer_client(indexer_client),
            # common is module-mocked at the top of this file for import isolation, so
            # _load_schema() needs a real INDEXER_PLUGINS_PATH pointed at it explicitly
            # instead of os.path.join(MagicMock(), ...). requires_indexer_templates
            # guarantees this path exists and holds the three real templates, so
            # _validate_documents() actually runs against them instead of being
            # bypassed. Note this only catches top-level shape mismatches:
            # _opensearch_template_to_jsonschema() sets additionalProperties: False
            # only at levels whose own template node declares dynamic: strict, not
            # recursively, so an extra *nested* field (the exact shape of the
            # wazuh.agent.config/host.os.full mismatch this PR removes) would still
            # pass local validation and only be caught by the live indexer itself.
            patch(
                "wazuh.core.indexer.metrics_snapshot.common.INDEXER_PLUGINS_PATH",
                INDEXER_TEMPLATES_PATH,
            ),
        ):
            await tasks._collect_and_index()

        for index in (
            "wazuh-metrics-agents",
            "wazuh-metrics-comms-v4",
            "wazuh-metrics-normalization",
        ):
            await indexer_client.indices.refresh(index=index)
            result = await indexer_client.search(
                index=index,
                body={"query": {"term": {"wazuh.cluster.node": self.NODE_NAME}}},
            )
            hits = result["hits"]["hits"]
            assert hits, (
                f"No document with wazuh.cluster.node={self.NODE_NAME} found in {index}"
            )
            source = hits[0]["_source"]

            # Parse the stored @timestamp the same way the index template's `date`
            # mapping (no explicit format) would. Checked against the indexed document,
            # not the normalizer's own return value — comparing to that would just
            # replay a _to_iso() regression instead of catching one, since both sides
            # would carry the same bad value.
            datetime.strptime(source["@timestamp"], "%Y-%m-%dT%H:%M:%SZ")

            if index == "wazuh-metrics-agents":
                assert source["wazuh"]["agent"]["id"] == "999"
                assert source["wazuh"]["agent"]["name"] == "itest-agent"
            elif index == "wazuh-metrics-comms-v4":
                assert source["event"]["module"] == "remoted"
                assert source["network"]["egress"]["bytes"] == 1
            else:
                assert source["metric"]["name"] == "itest.metric"
                assert source["metric"]["value"] == 1


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
