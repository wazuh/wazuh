"""Whole-agent deletion: DELETE /agents and its POST alias (authd's route)."""

import json

from helpers.session_builder import build_session, default_start

SYSTEM = "wazuh-states-inventory-system"
PACKAGES = "wazuh-states-inventory-packages"


def _seed(client, cluster, agent_id):
    values = [
        {"id": "os-1", "index": SYSTEM, "data": {"host": {"hostname": "h"}}},
        {"id": "pkg-1", "index": PACKAGES, "data": {"package": {"name": "zlib"}}},
    ]
    response = client.post_stateful(build_session(default_start(agent_id, cluster),
                                                  {"sync_data": {"values": values}}), agent_id=agent_id)
    assert response.status == 200, response.body


def test_delete_agent_wipes_only_that_agent(client, cluster, indexer, agent_id):
    survivor = f"{int(agent_id) + 1:03d}"
    _seed(client, cluster, agent_id)
    _seed(client, cluster, survivor)
    indexer.refresh()  # delete-by-query acts on the search view

    response = client.delete_agent(agent_id)
    assert response.status == 200, response.body
    assert json.loads(response.body) == {"status": "ok"}

    # 200 means the delete-by-query was FLUSHED, across every wazuh-states-* index.
    assert indexer.wait_for_docs(agent_id, 0) == []
    assert len(indexer.agent_docs(survivor)) == 2


def test_post_alias_behaves_identically(client, cluster, indexer, agent_id):
    _seed(client, cluster, agent_id)
    indexer.refresh()
    response = client.post_delete_agent_alias(agent_id)
    assert response.status == 200, response.body
    assert indexer.wait_for_docs(agent_id, 0) == []


def test_deleting_an_absent_agent_succeeds(client, agent_id):
    """404-as-success: repeating a delete (authd's retry) is harmless."""
    assert client.delete_agent(agent_id).status == 200
    assert client.delete_agent(agent_id).status == 200


def test_missing_or_invalid_target_is_400(client):
    assert client.delete_agent(None).status == 400
    assert client.delete_agent("not-numeric").status == 400


def test_delete_orders_after_the_same_agents_session(client, cluster, indexer, agent_id):
    """The deletion rides the agent's own shard: a session, then the delete,
    arrive in order -- the final state is 'deleted', never 'resurrected'."""
    _seed(client, cluster, agent_id)
    _seed(client, cluster, agent_id)  # a second in-flight-ish write
    indexer.refresh()

    assert client.delete_agent(agent_id).status == 200
    assert indexer.wait_for_docs(agent_id, 0) == []
