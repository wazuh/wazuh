"""Metadata and group reconciliation across the agent's indexed documents."""

import json

from helpers.session_builder import build_session, default_start

SYSTEM = "wazuh-states-inventory-system"
PACKAGES = "wazuh-states-inventory-packages"


def _ok(response):
    assert response.status == 200, response.body
    return json.loads(response.body)


def _seed(client, cluster, agent_id):
    values = [
        {"id": "os-1", "index": SYSTEM, "data": {"host": {"hostname": "seeded"}}},
        {"id": "pkg-1", "index": PACKAGES, "data": {"package": {"name": "zlib"}}},
    ]
    _ok(client.post_stateful(build_session(default_start(agent_id, cluster),
                                           {"sync_data": {"values": values}}), agent_id=agent_id))


def _metadata_session(cluster, agent_id, version, **overrides):
    start = default_start(agent_id, cluster, mode="metadata_delta",
                          indices=[SYSTEM, PACKAGES], global_version=version, **overrides)
    return build_session(start, None)


def test_metadata_delta_updates_every_declared_index(client, cluster, indexer, agent_id):
    _seed(client, cluster, agent_id)
    indexer.refresh()  # update-by-query works on the search view

    session = _metadata_session(cluster, agent_id, 100,
                                agentname="renamed-host", agentversion="5.1.0", hostname="new-hostname")
    assert _ok(client.post_stateful(session, agent_id=agent_id)) == {"status": "ok"}

    for document in indexer.wait_for_docs(agent_id, 2):
        source = document["_source"]
        assert source["wazuh"]["agent"]["name"] == "renamed-host", document["_index"]
        assert source["wazuh"]["agent"]["version"] == "5.1.0"
        assert source["wazuh"]["agent"]["host"]["hostname"] == "new-hostname"
        assert source["state"]["document_version"] == 100


def test_stale_metadata_never_overwrites_newer(client, cluster, indexer, agent_id):
    """The global_version guard: after v100 lands, a v50 writer is a no-op."""
    _seed(client, cluster, agent_id)
    indexer.refresh()
    _ok(client.post_stateful(_metadata_session(cluster, agent_id, 100, agentname="v100-name"),
                             agent_id=agent_id))
    indexer.refresh()

    _ok(client.post_stateful(_metadata_session(cluster, agent_id, 50, agentname="v50-name"),
                             agent_id=agent_id))

    for document in indexer.wait_for_docs(agent_id, 2):
        assert document["_source"]["wazuh"]["agent"]["name"] == "v100-name"
        assert document["_source"]["state"]["document_version"] == 100


def test_groups_delta_updates_groups(client, cluster, indexer, agent_id):
    _seed(client, cluster, agent_id)
    indexer.refresh()

    start = default_start(agent_id, cluster, mode="group_delta",
                          indices=[SYSTEM, PACKAGES], global_version=7,
                          groups=["webservers", "production"])
    assert _ok(client.post_stateful(build_session(start, None), agent_id=agent_id)) == {"status": "ok"}

    for document in indexer.wait_for_docs(agent_id, 2):
        assert document["_source"]["wazuh"]["agent"]["groups"] == ["webservers", "production"]
        assert document["_source"]["state"]["document_version"] == 7


def test_metadata_check_repairs_only_on_mismatch(client, cluster, indexer, agent_id):
    """The check variants are 'repair if needed': same metadata -> untouched
    (document_version keeps its value); different -> reconciled."""
    _seed(client, cluster, agent_id)
    indexer.refresh()
    _ok(client.post_stateful(_metadata_session(cluster, agent_id, 10), agent_id=agent_id))
    indexer.refresh()

    # A check claiming the SAME metadata must not bump document_version.
    start = default_start(agent_id, cluster, mode="metadata_check",
                          indices=[SYSTEM, PACKAGES], global_version=99)
    _ok(client.post_stateful(build_session(start, None), agent_id=agent_id))
    for document in indexer.wait_for_docs(agent_id, 2):
        assert document["_source"]["state"]["document_version"] == 10

    # A check with a DIFFERENT hostname repairs the field.
    start = default_start(agent_id, cluster, mode="metadata_check",
                          indices=[SYSTEM, PACKAGES], global_version=99, hostname="repaired")
    _ok(client.post_stateful(build_session(start, None), agent_id=agent_id))
    for document in indexer.wait_for_docs(agent_id, 2):
        assert document["_source"]["wazuh"]["agent"]["host"]["hostname"] == "repaired"


def test_metadata_over_forbidden_indices_is_a_noop(client, cluster, indexer, agent_id):
    _seed(client, cluster, agent_id)
    indexer.refresh()

    start = default_start(agent_id, cluster, mode="metadata_delta",
                          indices=["not-a-state-index"], global_version=100, agentname="never-applied")
    body = _ok(client.post_stateful(build_session(start, None), agent_id=agent_id))
    assert body == {"status": "ok", "noop": True}

    for document in indexer.wait_for_docs(agent_id, 2):
        assert document["_source"]["wazuh"]["agent"]["name"] == f"test-agent-{agent_id}"
