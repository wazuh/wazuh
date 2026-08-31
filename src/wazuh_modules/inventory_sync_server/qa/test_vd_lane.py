"""VD-flagged sessions under --no-vd: the D22 legitimate-skip row, end to end.

The harness deliberately does not start the vulnerability scanner facade; the
server's scanner seam then reports the feed ready and answers every scan as a
legitimate skip -- so a VD session still rides the scan lane and MUST index its
inventory and answer 200 (the same thing production does when the scanner is
disabled). The scan-gating rows (failed scan -> 500 and nothing indexed) are
pinned by the unit suite with an injectable scanner; the feed-download 503 +
Retry-After path is exercised by the vulnerability-detection integration
workflow, which runs this same server WITH the real scanner.
"""

import json

from helpers.session_builder import build_session, default_start

PACKAGES = "wazuh-states-inventory-packages"
SYSTEM = "wazuh-states-inventory-system"


def test_vdsync_session_skips_the_scan_and_indexes(client, cluster, indexer, agent_id):
    payload = {"sync_data": {
        "values": [{"id": "pkg-1", "index": PACKAGES, "data": {"package": {"name": "openssl", "version": "1.0"}}}],
        "contexts": [{"id": "os-ctx", "index": SYSTEM, "data": {"host": {"os": {"name": "Ubuntu"}}}}],
    }}
    session = build_session(default_start(agent_id, cluster, option="vdsync"), payload)
    response = client.post_stateful(session, agent_id=agent_id)
    assert response.status == 200, response.body
    assert json.loads(response.body) == {"status": "ok"}

    docs = indexer.wait_for_docs(agent_id, 1)
    assert docs[0]["_index"] == PACKAGES


def test_vdfirst_session_behaves_the_same(client, cluster, indexer, agent_id):
    session = build_session(default_start(agent_id, cluster, option="vdfirst"),
                            {"sync_data": {"values": [{"id": "pkg-2", "index": PACKAGES,
                                                       "data": {"package": {"name": "curl"}}}]}})
    assert client.post_stateful(session, agent_id=agent_id).status == 200
    assert len(indexer.wait_for_docs(agent_id, 1)) == 1


def test_vd_cleans_take_the_normal_pipeline(client, cluster, indexer, agent_id):
    """Only DATA sessions scan: a VD-flagged Cleans has nothing to scan and
    follows the ordinary pipeline."""
    seed = build_session(default_start(agent_id, cluster),
                         {"sync_data": {"values": [{"id": "pkg-3", "index": PACKAGES,
                                                    "data": {"package": {"name": "gone"}}}]}})
    assert client.post_stateful(seed, agent_id=agent_id).status == 200
    assert len(indexer.wait_for_docs(agent_id, 1)) == 1

    clean = build_session(default_start(agent_id, cluster, option="vdsync"), {"cleans": [PACKAGES]})
    assert client.post_stateful(clean, agent_id=agent_id).status == 200
    assert indexer.wait_for_docs(agent_id, 0) == []


def test_metrics_reflect_the_lane_traffic(client, cluster, indexer, agent_id):
    """GET /metrics is the observability contract F9c's monitor consumes; the
    skip counter moving proves the session really rode the scan lane."""
    before = {metric["name"]: metric["value"]
              for metric in json.loads(client.metrics().body)["metrics"]}

    session = build_session(default_start(agent_id, cluster, option="vdsync"),
                            {"sync_data": {"values": [{"id": "pkg-4", "index": PACKAGES,
                                                       "data": {"package": {"name": "m"}}}]}})
    assert client.post_stateful(session, agent_id=agent_id).status == 200

    after = {metric["name"]: metric["value"]
             for metric in json.loads(client.metrics().body)["metrics"]}
    assert after["vd.scans.skipped"] == before.get("vd.scans.skipped", 0) + 1
    assert after["sync.requests.total.200"] > before.get("sync.requests.total.200", 0)


# --- POST /_internal/vd/scan: the on-demand rescan the dispatcher drives -------------------------
#
# Under --no-vd the scanner seam reports "no scanner on this node", which the lane answers 503.
# NOT 200: the dispatcher records a 200 as `completed`, and in MANAGER_TASKS that means the scan was
# performed -- so a 200 here would file a scan that never ran as done. Retrying is bounded (vd_scan
# carries the default attempt budget, so it dead-letters rather than looping), and a scanner that
# comes back still does the work. The Ok path needs a real scanner and belongs to the
# vulnerability-detection integration workflow, which runs this same server with one.

NO_SCANNER_STATUS = 503


def test_an_on_demand_scan_is_answered_at_completion(client, agent_id):
    response = client.scan_agent({"agent_id": agent_id})
    assert response.status == NO_SCANNER_STATUS, response.body

    # The answer still comes from the lane, after the scan was attempted -- that is what "at
    # completion" means here. A different body would mean the request was refused short of it.
    body = json.loads(response.body)
    assert body["error"] == "no vulnerability scanner on this node"


def test_an_on_demand_scan_indexes_nothing(client, cluster, indexer, agent_id):
    """It carries no session and no inventory: VD reads the agent's stored packages itself. A
    document appearing here would mean the request fell through into the session path."""
    assert client.scan_agent({"agent_id": agent_id}).status == NO_SCANNER_STATUS
    assert indexer.agent_docs(agent_id) == []


def test_the_scan_agent_id_comes_from_the_body(client, agent_id):
    """No X-Wazuh-Agent-Id anywhere in the request -- the dispatcher sends none, so the body is the
    only channel. The header is ignored even when present, which is why a body without an id is a
    400 regardless.

    Reaching the scanner seam (503) rather than being rejected (400) is what proves the id was read
    from the body."""
    assert client.scan_agent({"agent_id": int(agent_id)}).status == NO_SCANNER_STATUS


def test_a_scan_body_that_names_no_agent_is_400(client):
    for body in (b"", b"not json", b"[]", {}, {"agent_id": None}, {"agent_id": "not-numeric"}):
        assert client.scan_agent(body).status == 400, f"body={body!r}"


def test_the_scan_metrics_move(client, agent_id):
    """The skip counter is what proves the request really rode the scan lane rather than being
    answered somewhere short of it."""
    before = {metric["name"]: metric["value"]
              for metric in json.loads(client.metrics().body)["metrics"]}

    assert client.scan_agent({"agent_id": agent_id}).status == NO_SCANNER_STATUS

    after = {metric["name"]: metric["value"]
             for metric in json.loads(client.metrics().body)["metrics"]}
    assert after["vd.scans.skipped"] == before.get("vd.scans.skipped", 0) + 1
