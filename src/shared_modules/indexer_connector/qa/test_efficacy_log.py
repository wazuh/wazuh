# SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
"""End-to-end checks of the indexer connector against a real OpenSearch, driven by
build/bin/indexer_connector_tool (testtool/main.cpp, push-events mode).

What the 5.x connector owns, and so what these tests pin:
  * every event pushed is indexed into the configured `index` (no template or mapping creation:
    the indexer plugins own the index, so the harness plays that part when a test needs a mapping);
  * a document the indexer rejects fails the flush loudly -- the tool exits 1 with
    "Bulk operation had indexing failures" and the item's status and reason are logged
    (indexerConnectorSyncImpl.hpp validateBulkResponse) -- instead of being dropped silently;
  * a 413 Payload Too Large splits the bulk recursively until every document lands;
  * an indexer outage fails the push, and nothing indexed before it is lost or duplicated after.

Inputs (configuration and events) are generated per test under pytest's tmp_path.
"""

import json
import logging
import re
import subprocess
import time
from pathlib import Path

import docker
import pytest
import requests

LOGGER = logging.getLogger(__name__)

SRC_DIR = Path(__file__).resolve().parents[3]
TOOL = SRC_DIR / "build" / "bin" / "indexer_connector_tool"

HOST = "localhost:9200"
BASE_URL = f"http://{HOST}"
IMAGE = "opensearchproject/opensearch:2.11.1"
CONTAINER = "indexer-connector-qa-opensearch"
TOOL_TIMEOUT = 300


# ─── OpenSearch ────────────────────────────────────────────────────────────────

def _remove_container(client):
    try:
        client.containers.get(CONTAINER).remove(force=True)
    except docker.errors.NotFound:
        pass


def wait_until_ready(timeout=180):
    """Waits for the node to answer and for the cluster to reach at least yellow."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            health = requests.get(f"{BASE_URL}/_cluster/health",
                                  params={"wait_for_status": "yellow", "timeout": "5s"}, timeout=10)
            if health.status_code == 200 and health.json().get("status") in ("green", "yellow"):
                return
        except requests.exceptions.RequestException:
            pass
        time.sleep(1)
    pytest.fail(f"OpenSearch was not ready after {timeout}s")


@pytest.fixture
def opensearch(request):
    """A fresh single-node OpenSearch per test. Parametrize indirectly with a dict of extra node
    settings (e.g. {"http.max_content_length": "1mb"}); the docker entrypoint turns dotted
    environment variables into node settings."""
    extra_settings = getattr(request, "param", None) or {}
    client = docker.from_env()
    _remove_container(client)
    environment = {
        "discovery.type": "single-node",
        "DISABLE_SECURITY_PLUGIN": "true",
        "OPENSEARCH_JAVA_OPTS": "-Xms512m -Xmx512m",
        **extra_settings,
    }
    container = client.containers.run(IMAGE, detach=True, name=CONTAINER, ports={"9200/tcp": 9200},
                                      environment=environment)
    try:
        wait_until_ready()
        yield container
    finally:
        _remove_container(client)


def count_documents(index):
    requests.post(f"{BASE_URL}/{index}/_refresh", timeout=30)
    response = requests.get(f"{BASE_URL}/{index}/_count", timeout=30)
    assert response.status_code == 200, f"_count on {index} failed: {response.text}"
    return response.json()["count"]


def put_cluster_setting(name, value):
    response = requests.put(f"{BASE_URL}/_cluster/settings",
                            json={"persistent": {name: value}}, timeout=30)
    assert response.status_code == 200, f"Setting {name} failed: {response.text}"


# ─── The tool ──────────────────────────────────────────────────────────────────

def make_event(i):
    return {
        "message": f"indexer connector qa event {i}",
        "agent": {"id": f"{i % 1000:03d}", "name": f"agent-{i}"},
        "package": {"name": "sample_package", "version": "1.0.0", "size": 12345},
    }


class Run:
    def __init__(self, completed, log_text):
        self.returncode = completed.returncode
        self.output = completed.stdout + completed.stderr
        self.log = log_text

    def text(self):
        return self.output + self.log


def run_tool(tmp_path, name, index, events, *extra_args, **config_overrides):
    """Runs push-events once and waits for it to exit (-w 1 keeps it from waiting on stdin).
    The tool runs from src/, where the keystore it seeds credentials into lives (queue/keystore)."""
    assert TOOL.exists(), f"{TOOL} was not built"

    config = {"index": index, "hosts": [BASE_URL], "username": "admin", "password": "admin",
              **config_overrides}
    config_file = tmp_path / f"{name}.config.json"
    events_file = tmp_path / f"{name}.events.json"
    log_file = tmp_path / f"{name}.log"
    config_file.write_text(json.dumps(config))
    events_file.write_text(json.dumps(events))

    command = [str(TOOL), "-c", str(config_file), "-e", str(events_file), "-w", "1",
               "-l", str(log_file), *extra_args]
    LOGGER.info("Running %s", " ".join(command))
    completed = subprocess.run(command, cwd=SRC_DIR, capture_output=True, text=True, timeout=TOOL_TIMEOUT)
    run = Run(completed, log_file.read_text() if log_file.exists() else "")
    LOGGER.info("Exit code %d", run.returncode)
    if run.returncode != 0:
        LOGGER.info("Tool output:\n%s\nTool log:\n%s", run.output[-4000:], run.log[-4000:])
    return run


# ─── Tests ─────────────────────────────────────────────────────────────────────

def test_opensearch_health(opensearch):
    response = requests.get(f"{BASE_URL}/_cluster/health", timeout=30)
    assert response.status_code == 200
    assert response.json()["status"] in ("green", "yellow")


def test_sync_push_indexes_every_event(opensearch, tmp_path):
    index = "wazuh-qa-sync"
    events = [make_event(i) for i in range(3)]

    first = run_tool(tmp_path, "first", index, events)
    assert first.returncode == 0, "The push failed"
    assert count_documents(index) == len(events)

    # The tool's ids are positional (doc-0 ... doc-N), so pushing the same events again overwrites
    # them: a re-sent batch must not duplicate documents.
    second = run_tool(tmp_path, "second", index, events)
    assert second.returncode == 0, "The second push failed"
    assert count_documents(index) == len(events)


def test_async_push_drains_into_the_index(opensearch, tmp_path):
    index = "wazuh-qa-async"
    events = [make_event(i) for i in range(50)]

    run = run_tool(tmp_path, "async", index, events, "-m", "async")
    assert run.returncode == 0, "The async push failed"
    assert count_documents(index) == len(events)


@pytest.mark.parametrize("opensearch", [{"http.max_content_length": "1mb"}], indirect=True)
def test_payload_too_large_is_split_until_everything_lands(opensearch, tmp_path):
    index = "wazuh-qa-413"
    # ~1.2 KB per document: ~5 MB in one bulk, under the connector's 16 MB bulk size set below but
    # five times the node's 1 MB limit, so the first request is answered 413 and split recursively.
    base = make_event(0)
    base["padding"] = "x" * 1024
    events = [dict(base, message=f"event {i}") for i in range(4000)]

    run = run_tool(tmp_path, "split", index, events, max_bulk_size=16 * 1024 * 1024)
    assert run.returncode == 0, "The push failed"
    assert "Received 413 error (Payload Too Large). Splitting bulk data." in run.log, \
        "The bulk was never answered 413, so the split path was not exercised"
    assert count_documents(index) == len(events)


def test_rejected_document_fails_the_flush_until_the_mapping_allows_it(opensearch, tmp_path):
    index = "wazuh-qa-mapping"
    # The indexer plugins own the mapping in 5.x; here the harness plays that part.
    mapping = {"mappings": {"dynamic": "strict", "properties": {"message": {"type": "keyword"}}}}
    response = requests.put(f"{BASE_URL}/{index}", json=mapping, timeout=30)
    assert response.status_code == 200, response.text

    events = [{"message": "first", "unexpected": "field the mapping does not have"}]

    rejected = run_tool(tmp_path, "rejected", index, events)
    assert rejected.returncode == 1, "A rejected document must fail the push"
    assert "Bulk operation had indexing failures" in rejected.output
    assert "Indexing failure for index operation (status 400)" in rejected.log
    assert "dynamic introduction of [unexpected]" in rejected.log
    assert count_documents(index) == 0

    response = requests.put(f"{BASE_URL}/{index}/_mapping",
                            json={"properties": {"unexpected": {"type": "keyword"}}}, timeout=30)
    assert response.status_code == 200, response.text

    accepted = run_tool(tmp_path, "accepted", index, events)
    assert accepted.returncode == 0, "The same push must succeed once the mapping allows it"
    assert count_documents(index) == 1


def test_shard_limit_rejection_is_reported(opensearch, tmp_path):
    # A new index needs a primary and a replica: two shards against a limit of one.
    put_cluster_setting("cluster.max_shards_per_node", 1)

    run = run_tool(tmp_path, "shards", "wazuh-qa-shards", [make_event(0)])
    assert run.returncode == 1, "A rejected index creation must fail the push"
    assert "Bulk operation had indexing failures" in run.output
    assert "Indexing failure for index operation (status 400)" in run.log
    assert re.search(r"maximum.*shards open", run.log), "The shard-limit reason was not logged"


def test_missing_index_rejection_is_reported(opensearch, tmp_path):
    index = "wazuh-qa-missing"
    put_cluster_setting("action.auto_create_index", False)

    run = run_tool(tmp_path, "missing", index, [make_event(0)])
    assert run.returncode == 1, "A bulk to a missing index must fail the push"
    assert "Bulk operation had indexing failures" in run.output
    assert "Indexing failure for index operation (status 404)" in run.log
    assert f"no such index [{index}]" in run.log
    assert requests.head(f"{BASE_URL}/{index}", timeout=30).status_code == 404


def test_outage_fails_the_push_and_loses_nothing(opensearch, tmp_path):
    index = "wazuh-qa-outage"
    events = [make_event(i) for i in range(3)]

    before = run_tool(tmp_path, "before", index, events)
    assert before.returncode == 0, "The push with the indexer up failed"
    assert count_documents(index) == len(events)

    opensearch.stop()

    # Small retry budget: with the node down the push has to fail, not hang and not report success.
    during = run_tool(tmp_path, "during", index, events, max_retry_attempts=2, max_retry_duration_seconds=5)
    assert during.returncode != 0, "A push with the indexer down must not succeed"
    assert re.search(r"No available server|Transport-level failure|retry budget exhausted", during.text()), \
        "The outage was not reported"

    opensearch.start()
    wait_until_ready()
    assert count_documents(index) == len(events), "Documents indexed before the outage were lost"

    after = run_tool(tmp_path, "after", index, events)
    assert after.returncode == 0, "The push after recovery failed"
    assert count_documents(index) == len(events), "The push after recovery duplicated documents"


def test_repeated_flushes_do_not_resend(opensearch, tmp_path):
    index = "wazuh-qa-flush-loop"
    events = [make_event(i) for i in range(3)]

    # -L: flush() called again and again on an already-flushed (empty) buffer (main.cpp, sync only).
    run = run_tool(tmp_path, "loop", index, events, "-L", "10", "-D", "0")
    assert run.returncode == 0, "Repeated flushes failed"
    assert "Flush call 10/10" in run.output
    assert count_documents(index) == len(events)
