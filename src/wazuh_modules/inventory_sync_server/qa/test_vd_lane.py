"""VD-flagged sessions under --no-vd: a session no scanner can scan is deferred.

The harness deliberately does not start the vulnerability scanner facade. Every
node runs the scanner, so the server never treats a missing one as "nothing to
scan": a VD data session and an on-demand scan are both answered 503 with a
Retry-After, and nothing is indexed -- a 200 would have the agent record as
delivered an inventory that no scanner has seen. The scan-gating rows (failed
scan -> 500 and nothing indexed, nothing to scan -> index + 200) are pinned by
the unit suite with an injectable scanner; the scanned path is exercised by the
vulnerability-detection integration workflow, which runs this same server WITH
the real scanner.
"""

import json

from helpers.session_builder import build_session, default_start

PACKAGES = "wazuh-states-inventory-packages"
SYSTEM = "wazuh-states-inventory-system"

DEFERRED_STATUS = 503
DEFERRED_ERROR = "vulnerability feed not ready"


def _assert_deferred(response):
    assert response.status == DEFERRED_STATUS, response.body
    assert json.loads(response.body)["error"] == DEFERRED_ERROR
    assert int(response.headers["retry-after"]) > 0


def test_vdsync_session_is_deferred_and_indexes_nothing(client, cluster, indexer, agent_id):
    payload = {"sync_data": {
        "values": [{"id": "pkg-1", "index": PACKAGES, "data": {"package": {"name": "openssl", "version": "1.0"}}}],
        "contexts": [{"id": "os-ctx", "index": SYSTEM, "data": {"host": {"os": {"name": "Ubuntu"}}}}],
    }}
    session = build_session(default_start(agent_id, cluster, option="vdsync"), payload)
    _assert_deferred(client.post_stateful(session, agent_id=agent_id))
    assert indexer.agent_docs(agent_id) == []


def test_vdfirst_session_behaves_the_same(client, cluster, indexer, agent_id):
    session = build_session(default_start(agent_id, cluster, option="vdfirst"),
                            {"sync_data": {"values": [{"id": "pkg-2", "index": PACKAGES,
                                                       "data": {"package": {"name": "curl"}}}]}})
    _assert_deferred(client.post_stateful(session, agent_id=agent_id))
    assert indexer.agent_docs(agent_id) == []


def test_vd_cleans_take_the_normal_pipeline(client, cluster, indexer, agent_id):
    """Only DATA sessions scan: a VD-flagged Cleans has nothing to scan and
    follows the ordinary pipeline, scanner or not."""
    seed = build_session(default_start(agent_id, cluster),
                         {"sync_data": {"values": [{"id": "pkg-3", "index": PACKAGES,
                                                    "data": {"package": {"name": "gone"}}}]}})
    assert client.post_stateful(seed, agent_id=agent_id).status == 200
    assert len(indexer.wait_for_docs(agent_id, 1)) == 1

    clean = build_session(default_start(agent_id, cluster, option="vdsync"), {"cleans": [PACKAGES]})
    assert client.post_stateful(clean, agent_id=agent_id).status == 200
    assert indexer.wait_for_docs(agent_id, 0) == []


def test_metrics_count_the_deferred_session(client, cluster, agent_id):
    """GET /metrics is the observability contract the monitor consumes: a deferred session is a
    503 with a Retry-After, and never a scan of any kind."""
    before = {metric["name"]: metric["value"]
              for metric in json.loads(client.metrics().body)["metrics"]}

    session = build_session(default_start(agent_id, cluster, option="vdsync"),
                            {"sync_data": {"values": [{"id": "pkg-4", "index": PACKAGES,
                                                       "data": {"package": {"name": "m"}}}]}})
    _assert_deferred(client.post_stateful(session, agent_id=agent_id))

    after = {metric["name"]: metric["value"]
             for metric in json.loads(client.metrics().body)["metrics"]}
    assert after["sync.requests.total.503"] > before.get("sync.requests.total.503", 0)
    for name in ("vd.scans.ok", "vd.scans.skipped", "vd.scans.failed"):
        assert after.get(name, 0) == before.get(name, 0), name


# --- POST /_internal/vd/scan: the on-demand rescan the dispatcher drives -------------------------
#
# Under --no-vd there is no scanner to run it, which the lane answers 503. NOT 200: the dispatcher
# records a 200 as `completed`, and in MANAGER_TASKS that means the scan was performed -- so a 200
# here would file a scan that never ran as done. Retrying is bounded (vd_scan carries the default
# attempt budget, so it dead-letters rather than looping), and a scanner that comes back still does
# the work. The Ok path needs a real scanner and belongs to the vulnerability-detection integration
# workflow, which runs this same server with one.


def test_an_on_demand_scan_without_a_scanner_is_deferred(client, agent_id):
    _assert_deferred(client.scan_agent({"agent_id": agent_id}))


def test_an_on_demand_scan_indexes_nothing(client, cluster, indexer, agent_id):
    """It carries no session and no inventory: VD reads the agent's stored packages itself. A
    document appearing here would mean the request fell through into the session path."""
    assert client.scan_agent({"agent_id": agent_id}).status == DEFERRED_STATUS
    assert indexer.agent_docs(agent_id) == []


def test_the_scan_agent_id_comes_from_the_body(client, agent_id):
    """No X-Wazuh-Agent-Id anywhere in the request -- the dispatcher sends none, so the body is the
    only channel. The header is ignored even when present, which is why a body without an id is a
    400 regardless.

    Reaching the scan lane (503) rather than being rejected (400) is what proves the id was read
    from the body."""
    assert client.scan_agent({"agent_id": int(agent_id)}).status == DEFERRED_STATUS


def test_a_scan_body_that_names_no_agent_is_400(client):
    for body in (b"", b"not json", b"[]", {}, {"agent_id": None}, {"agent_id": "not-numeric"}):
        assert client.scan_agent(body).status == 400, f"body={body!r}"
