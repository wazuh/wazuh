"""The post-deletion sweep: a report that lands after the agent's deletion is removed one window later.

A whole-agent deletion cancel()s the agent's pending reports and deletes its two `wazuh-agent-*` documents
by id on an ordered bucket, but the cancel also lifts the ambiguous-retry pin of a report that timed out on a
node (IC README, Ordered buckets): such a node may still apply the report after the delete reached another one.
The sweeper note()s every agent whose by-id deletes succeeded and, one window later (the runtime's request
timeout + 5 s), deletes by id -- one delete-by-query per index -- whatever was written for it meanwhile.

The test plays that late write itself: it puts a document straight into the indexer after the 200. It runs on a
server of its own whose request timeout is 2 s, so the window is 7 s and not 65 s.
"""

import json
import os
import pathlib
import time

import pytest

from helpers.indexer import AGENT_STATS_INDEX
from helpers import testtool

CONFIG = json.loads((pathlib.Path(__file__).resolve().parent / "config.json").read_text())

REQUEST_TIMEOUT_MS = 2000
SWEEP_MARGIN_S = 5  # added to the request timeout by the module
WINDOW_S = REQUEST_TIMEOUT_MS / 1000 + SWEEP_MARGIN_S

RESIDUAL = "sync.agent_delete.sweep.residual"


@pytest.fixture(scope="module")
def sweep_server(indexer, tmp_path_factory):
    """A server of its own, same pattern as conftest's `server`, with a short indexer request timeout.

    `internal_options` is the testtool's channel for the indexer client's runtime options (the text
    `key=value` lines of etc/wazuh-manager-internal-options.conf)."""
    workdir = tmp_path_factory.mktemp("sweep_server")
    config = dict(CONFIG)
    config["indexer"] = {**CONFIG["indexer"],
                         "hosts": [os.environ.get("INDEXER_URL", CONFIG["indexer"]["hosts"][0])]}
    config["internal_options"] = f"wazuh_modules.indexer_client_request_timeout_ms={REQUEST_TIMEOUT_MS}\n"

    process, socket_path = testtool.start_server(testtool.testtool_path(), workdir, config)
    yield str(socket_path)
    testtool.stop_server(process)


@pytest.fixture()
def sweep_client(sweep_server):
    from helpers.uds_client import ServerClient

    return ServerClient(sweep_server)


def _metric(client, name):
    document = json.loads(client.metrics().body)
    values = [entry["value"] for entry in document["metrics"] if entry["name"] == name]
    assert len(values) == 1, f"{name} must be published exactly once, got {values}"
    return values[0]


def test_sweep_removes_late_report(sweep_client, indexer, agent_id):
    # An ordinary deletion of an agent that reported once: both by-id deletes succeed, so it is note()d.
    assert sweep_client.post_stats({"modules": {"agent": {"uptime": 1}}}, agent_id=agent_id).status == 200
    landed = indexer.wait_for_docs(agent_id, 1, index=AGENT_STATS_INDEX, timeout=30)
    assert landed, "the report never landed"
    residual_before = _metric(sweep_client, RESIDUAL)

    assert sweep_client.delete_agent({"agent_id": agent_id}).status == 200
    assert indexer.agent_docs(agent_id, index=AGENT_STATS_INDEX) == [], "the deletion itself must remove it"

    # The late write: the same report applied again after the delete, as a node that had timed out on it would.
    # It is the document the server built, so it fits the index's strict mapping (an invented field is a 400).
    indexer.put_doc(AGENT_STATS_INDEX, agent_id, landed[0]["_source"])
    assert indexer.get(AGENT_STATS_INDEX, agent_id) is not None, "the late document must exist before the sweep"

    # It is due one window after the deletion and the sweep ticks once per window: gone within two windows
    # (plus the slack of a loaded CI machine).
    deadline = time.monotonic() + 2 * WINDOW_S + 10
    while time.monotonic() < deadline and indexer.get(AGENT_STATS_INDEX, agent_id) is not None:
        time.sleep(0.5)

    assert indexer.get(AGENT_STATS_INDEX, agent_id) is None, \
        f"the sweep left the late report of agent {agent_id} in {AGENT_STATS_INDEX}"
    # Exactly the one document: the sweep deletes by id, and the counter is the number it deleted.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and _metric(sweep_client, RESIDUAL) - residual_before < 1:
        time.sleep(0.2)
    assert _metric(sweep_client, RESIDUAL) - residual_before == 1, \
        "sync.agent_delete.sweep.residual must grow by the one document the sweep deleted"
