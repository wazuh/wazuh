"""Transport-level rejections and the FullSession validation matrix.

Every case here must be answered WITHOUT touching the indexer: they are the
strand-side 400/403 contract remoted relays verbatim to the agent.
"""

import json

import pytest

from helpers.session_builder import build_non_full_session_message, build_session, default_start


def _error(response):
    return json.loads(response.body)


def test_health_probe(client):
    response = client.health()
    assert response.status == 200
    assert json.loads(response.body)["status"] == "ok"


def test_missing_agent_id_header_is_400(client, cluster, agent_id):
    session = build_session(default_start(agent_id, cluster),
                            {"sync_data": {"values": [{"id": "d1", "index": "wazuh-states-inventory-system",
                                                       "data": {"host": {"ip": "10.0.0.1"}}}]}})
    response = client.post_stateful(session, agent_id=None)
    assert response.status == 400


def test_non_numeric_agent_id_header_is_400(client, cluster, agent_id):
    session = build_session(default_start(agent_id, cluster),
                            {"sync_data": {"values": [{"id": "d1", "index": "wazuh-states-inventory-system",
                                                       "data": {}}]}})
    response = client.post_stateful(session, agent_id="not-a-number")
    assert response.status == 400


def test_empty_body_is_400(client, agent_id):
    assert client.post_stateful(b"", agent_id=agent_id).status == 400


def test_garbage_body_is_400(client, agent_id):
    assert client.post_stateful(b"this is not a flatbuffer at all", agent_id=agent_id).status == 400


def test_non_full_session_message_is_400(client, cluster, agent_id):
    """A well-formed Message carrying a bare Start (a legacy union member):
    only Message{FullSession} is a session."""
    response = client.post_stateful(build_non_full_session_message(agent_id, cluster), agent_id=agent_id)
    assert response.status == 400


def test_identity_mismatch_is_403(client, cluster, agent_id):
    """Start.agentid must match the AUTHENTICATED header identity."""
    other = f"{int(agent_id) + 1:03d}"
    session = build_session(default_start(other, cluster),
                            {"sync_data": {"values": [{"id": "d1", "index": "wazuh-states-inventory-system",
                                                       "data": {}}]}})
    response = client.post_stateful(session, agent_id=agent_id)
    assert response.status == 403
    assert _error(response)["code"] == 403


def test_foreign_cluster_is_403(client, agent_id):
    session = build_session(default_start(agent_id, "someone-elses-cluster"),
                            {"sync_data": {"values": [{"id": "d1", "index": "wazuh-states-inventory-system",
                                                       "data": {}}]}})
    assert client.post_stateful(session, agent_id=agent_id).status == 403


def test_agent_id_padding_is_normalized(client, cluster, indexer, agent_id):
    """Header '42' and Start '042' are the same numeric identity (the wire
    strips or pads; the server compares numerically)."""
    unpadded = str(int(agent_id))
    session = build_session(default_start(agent_id, cluster),
                            {"sync_data": {"values": [{"id": "pad-doc", "index": "wazuh-states-inventory-system",
                                                       "data": {"host": {"hostname": "padded"}}}]}})
    response = client.post_stateful(session, agent_id=unpadded)
    assert response.status == 200

    docs = indexer.wait_for_docs(agent_id, 1)
    assert len(docs) == 1


@pytest.mark.parametrize(
    "mode,payload",
    [
        # ModuleDelta requires a payload...
        ("delta", None),
        # ...and ModuleCheck requires exactly a ChecksumModule.
        ("check", None),
        ("check", {"sync_data": {"values": [{"id": "d", "index": "wazuh-states-inventory-system", "data": {}}]}}),
        ("delta", {"checksum": {"index": "wazuh-states-inventory-system", "checksum": "aa"}}),
        # Metadata/group modes are Start-only: any payload is a shape error.
        ("metadata_delta", {"sync_data": {"values": [{"id": "d", "index": "wazuh-states-inventory-system",
                                                      "data": {}}]}}),
        ("group_check", {"cleans": ["wazuh-states-inventory-system"]}),
    ],
)
def test_mode_payload_matrix_rejections(client, cluster, agent_id, mode, payload):
    start = default_start(agent_id, cluster, mode=mode,
                          indices=["wazuh-states-inventory-system"], global_version=1)
    response = client.post_stateful(build_session(start, payload), agent_id=agent_id)
    assert response.status == 400, response.body


def test_empty_values_is_400(client, cluster, agent_id):
    """D8: SyncData with an empty values vector carries nothing to sync."""
    session = build_session(default_start(agent_id, cluster), {"sync_data": {"values": []}})
    assert client.post_stateful(session, agent_id=agent_id).status == 400


def test_checksum_without_index_is_400(client, cluster, agent_id):
    session = build_session(default_start(agent_id, cluster, mode="check"),
                            {"checksum": {"checksum": "deadbeef"}})
    assert client.post_stateful(session, agent_id=agent_id).status == 400


def test_checksum_without_value_is_400(client, cluster, agent_id):
    session = build_session(default_start(agent_id, cluster, mode="check"),
                            {"checksum": {"index": "wazuh-states-inventory-system"}})
    assert client.post_stateful(session, agent_id=agent_id).status == 400


def test_unknown_route_is_404_and_wrong_verb_is_405(client):
    assert client._request("POST", "/no-such-route", body=b"x").status == 404
    response = client._request("PUT", "/stateful", body=b"x")
    assert response.status == 405
    assert "allow" in response.headers
