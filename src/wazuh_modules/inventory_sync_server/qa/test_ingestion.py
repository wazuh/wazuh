"""ModuleDelta x SyncData: what actually lands in the state indices.

The legacy suite asserted protocol acks and never read a document back; these
tests assert the real contract -- _id shape, the authoritative wazuh.* overlay,
per-document skip policy, and idempotent re-POSTs.
"""

import json

from helpers.session_builder import build_session, default_start

SYSTEM = "wazuh-states-inventory-system"
PACKAGES = "wazuh-states-inventory-packages"


def _ok(response):
    assert response.status == 200, response.body
    return json.loads(response.body)


def test_basic_flow_indexes_one_document(client, cluster, indexer, agent_id):
    session = build_session(
        default_start(agent_id, cluster),
        {"sync_data": {"values": [{"id": "doc123", "index": SYSTEM,
                                   "data": {"host": {"ip": "192.168.1.100", "hostname": "webserver"}}}]}})
    body = _ok(client.post_stateful(session, agent_id=agent_id))
    assert body == {"status": "ok"}

    docs = indexer.wait_for_docs(agent_id, 1)
    assert len(docs) == 1
    document = docs[0]
    # _id = {cluster}_{agent}_{document id}: the cluster scoping that keeps two
    # same-numbered agents of different clusters from colliding.
    assert document["_id"] == f"{cluster}_{agent_id}_doc123"
    assert document["_index"] == SYSTEM
    source = document["_source"]
    assert source["host"]["ip"] == "192.168.1.100"
    # The manager-controlled overlay.
    assert source["wazuh"]["agent"]["id"] == agent_id
    assert source["wazuh"]["agent"]["name"] == f"test-agent-{agent_id}"
    assert source["wazuh"]["agent"]["groups"] == ["default"]
    assert source["wazuh"]["agent"]["host"]["os"]["platform"] == "ubuntu"
    assert source["wazuh"]["cluster"]["name"] == cluster


def test_overlay_defeats_impersonation(client, cluster, indexer, agent_id):
    """A payload claiming another agent's identity under wazuh.* is clobbered
    by the authenticated one, byte for byte."""
    session = build_session(
        default_start(agent_id, cluster),
        {"sync_data": {"values": [{"id": "spoof", "index": SYSTEM,
                                   "data": {"wazuh": {"agent": {"id": "999", "name": "evil"},
                                                      "cluster": {"name": "evil-cluster"}},
                                            "host": {"hostname": "h"}}}]}})
    _ok(client.post_stateful(session, agent_id=agent_id))

    docs = indexer.wait_for_docs(agent_id, 1)
    source = docs[0]["_source"]
    assert source["wazuh"]["agent"]["id"] == agent_id
    assert source["wazuh"]["agent"]["name"] == f"test-agent-{agent_id}"
    assert source["wazuh"]["cluster"]["name"] == cluster
    # And nothing was indexed under the forged identity.
    assert indexer.agent_docs("999") == []


def test_multi_index_session(client, cluster, indexer, agent_id):
    values = [
        {"id": "os-1", "index": SYSTEM, "data": {"host": {"hostname": "h1"}}},
        {"id": "pkg-1", "index": PACKAGES, "data": {"package": {"name": "openssl", "version": "3.0"}}},
        {"id": "pkg-2", "index": PACKAGES, "data": {"package": {"name": "curl", "version": "8.0"}}},
    ]
    _ok(client.post_stateful(build_session(default_start(agent_id, cluster),
                                           {"sync_data": {"values": values}}), agent_id=agent_id))

    docs = indexer.wait_for_docs(agent_id, 3)
    by_index = {}
    for document in docs:
        by_index.setdefault(document["_index"], []).append(document["_id"])
    assert len(by_index[SYSTEM]) == 1
    assert len(by_index[PACKAGES]) == 2


def test_delete_operation_removes_the_document(client, cluster, indexer, agent_id):
    upsert = build_session(default_start(agent_id, cluster),
                           {"sync_data": {"values": [{"id": "gone", "index": SYSTEM,
                                                      "data": {"host": {"hostname": "temp"}}}]}})
    _ok(client.post_stateful(upsert, agent_id=agent_id))
    assert len(indexer.wait_for_docs(agent_id, 1)) == 1

    delete = build_session(default_start(agent_id, cluster),
                           {"sync_data": {"values": [{"id": "gone", "index": SYSTEM,
                                                      "operation": "delete"}]}})
    _ok(client.post_stateful(delete, agent_id=agent_id))
    assert indexer.wait_for_docs(agent_id, 0) == []


def test_forbidden_index_is_skipped_but_the_session_succeeds(client, cluster, indexer, agent_id):
    """Per-document policy: a value aimed outside wazuh-states-* is skipped
    with a warning; the valid siblings still land and the session answers ok."""
    values = [
        {"id": "bad", "index": "forbidden-index", "data": {"x": 1}},
        {"id": "good", "index": SYSTEM, "data": {"host": {"hostname": "ok"}}},
    ]
    body = _ok(client.post_stateful(build_session(default_start(agent_id, cluster),
                                                  {"sync_data": {"values": values}}), agent_id=agent_id))
    assert body == {"status": "ok"}

    docs = indexer.wait_for_docs(agent_id, 1)
    assert docs[0]["_id"].endswith("_good")
    assert indexer.search(index="forbidden-index") == []


def test_vulnerabilities_index_is_write_protected(client, cluster, indexer, agent_id):
    """Agents may clean wazuh-states-vulnerabilities, never write it (the
    manager's scanner is its only producer)."""
    values = [{"id": "cve", "index": "wazuh-states-vulnerabilities",
               "data": {"vulnerability": {"id": "CVE-2024-0001"}}}]
    body = _ok(client.post_stateful(build_session(default_start(agent_id, cluster),
                                                  {"sync_data": {"values": values}}), agent_id=agent_id))
    assert body == {"status": "ok", "noop": True}
    assert indexer.agent_docs(agent_id) == []


def test_all_skipped_is_a_noop_200(client, cluster, indexer, agent_id):
    values = [
        {"id": "", "index": SYSTEM, "data": {"host": {}}},        # empty id
        {"id": "b", "index": "not-a-state-index", "data": {}},    # forbidden index
        {"id": "c", "index": SYSTEM, "data": b"not json at all"}, # malformed document
    ]
    body = _ok(client.post_stateful(build_session(default_start(agent_id, cluster),
                                                  {"sync_data": {"values": values}}), agent_id=agent_id))
    assert body == {"status": "ok", "noop": True}
    assert indexer.agent_docs(agent_id) == []


def test_re_post_is_idempotent(client, cluster, indexer, agent_id):
    """The whole retry contract: same buffer, same result, same documents."""
    session = build_session(
        default_start(agent_id, cluster),
        {"sync_data": {"values": [{"id": "stable", "index": SYSTEM,
                                   "data": {"host": {"hostname": "same"}}}]}})
    first = _ok(client.post_stateful(session, agent_id=agent_id))
    second = _ok(client.post_stateful(session, agent_id=agent_id))
    assert first == second == {"status": "ok"}

    docs = indexer.wait_for_docs(agent_id, 1)
    assert len(docs) == 1
    assert docs[0]["_id"] == f"{cluster}_{agent_id}_stable"


def test_data_contexts_are_not_indexed(client, cluster, indexer, agent_id):
    """DataContext items feed the vulnerability scanner's context; they never
    become state documents on their own."""
    payload = {"sync_data": {
        "values": [{"id": "v1", "index": PACKAGES, "data": {"package": {"name": "zlib"}}}],
        "contexts": [{"id": "ctx1", "index": SYSTEM, "data": {"host": {"hostname": "ctx"}}}],
    }}
    _ok(client.post_stateful(build_session(default_start(agent_id, cluster), payload), agent_id=agent_id))

    docs = indexer.wait_for_docs(agent_id, 1)
    assert docs[0]["_index"] == PACKAGES
