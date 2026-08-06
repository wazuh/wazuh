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
