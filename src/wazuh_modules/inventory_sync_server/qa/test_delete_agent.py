"""Whole-agent deletion: DELETE /agents and its POST alias (authd's route)."""

import json

from helpers.indexer import AGENT_CONFIG_INDEX, AGENT_STATS_INDEX
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


# /config and /stats are written by the ASYNC connector, which answers 200 before the document
# reaches the indexer. config.json drops its flush interval to 1 s for the suite; this ceiling is
# the slack a loaded CI machine needs on top of that, not the interval itself.
ASYNC_WRITE_TIMEOUT = 30


def _seed_config_and_stats(client, agent_id):
    """The two HTTPS reports that land outside the wazuh-states-* family."""
    assert client.post_config({"modules": {"agent": {"name": "a"}}}, agent_id=agent_id).status == 200
    assert client.post_stats({"modules": {"agent": {"uptime": 1}}}, agent_id=agent_id).status == 200


def _await_config_and_stats(indexer, agent_id):
    """Blocks until both async writes are searchable. Asserting on their absence later would
    otherwise pass for the wrong reason: nothing was there to delete."""
    for index in (AGENT_CONFIG_INDEX, AGENT_STATS_INDEX):
        docs = indexer.wait_for_docs(agent_id, 1, index=index, timeout=ASYNC_WRITE_TIMEOUT)
        assert docs, f"agent {agent_id} has no document in {index} after {ASYNC_WRITE_TIMEOUT}s"


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


def test_delete_agent_wipes_config_and_stats_too(client, cluster, indexer, agent_id):
    """The regression this endpoint had: `wazuh-agent-config` and `wazuh-agent-stats`
    live outside `wazuh-states-*`, so the states pattern alone left them behind -- and
    with the agent gone from client.keys nothing ever overwrote them again."""
    survivor = f"{int(agent_id) + 1:03d}"
    _seed(client, cluster, agent_id)
    _seed_config_and_stats(client, agent_id)
    _seed_config_and_stats(client, survivor)

    _await_config_and_stats(indexer, agent_id)
    _await_config_and_stats(indexer, survivor)

    assert client.delete_agent(agent_id).status == 200

    for pattern, docs in indexer.agent_docs_in_scope(agent_id).items():
        assert docs == [], f"agent {agent_id} still has documents in {pattern}"

    # Scoped: the deletion is per agent, not a wipe of the shared indices.
    assert len(indexer.agent_docs(survivor, index=AGENT_CONFIG_INDEX)) == 1
    assert len(indexer.agent_docs(survivor, index=AGENT_STATS_INDEX)) == 1


def test_delete_sees_documents_written_inside_the_refresh_interval(client, cluster, indexer, agent_id):
    """No indexer.refresh() here, deliberately. A delete-by-query is a SEARCH, and the
    state indices refresh every 2 s; authd deletes right behind the agent's last session,
    so without the server refreshing first this deletion answers 200 having matched
    nothing and the documents survive forever.

    Only the state documents are seeded: they are written synchronously, so the session's
    200 means they ARE in the indexer, just not searchable yet -- which is exactly the
    window under test. Seeding /config and /stats here would prove nothing, since their
    async write may not have reached the indexer at all by the time the deletion runs."""
    _seed(client, cluster, agent_id)

    assert client.delete_agent(agent_id).status == 200

    assert indexer.agent_docs(agent_id) == [], \
        "the deletion missed state documents that were flushed but not yet refreshed"


def test_post_alias_behaves_identically(client, cluster, indexer, agent_id):
    _seed(client, cluster, agent_id)
    indexer.refresh()
    response = client.post_delete_agent_alias(agent_id)
    assert response.status == 200, response.body
    assert indexer.wait_for_docs(agent_id, 0) == []


def test_deleting_an_absent_agent_succeeds(client, agent_id):
    """404-as-success: repeating a delete (authd's retry) is harmless, and it stays
    quiet -- refreshing an index that was never created is a no-op, not a warning."""
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
