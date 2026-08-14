"""Cleans sessions and the composed full resync (D19: Cleans + ModuleDelta)."""

import json

from helpers.session_builder import build_session, default_start

FILES = "wazuh-states-fim-files"
KEYS = "wazuh-states-fim-registry-keys"
SYSTEM = "wazuh-states-inventory-system"


def _ok(response):
    assert response.status == 200, response.body
    return json.loads(response.body)


def _seed(client, cluster, agent_id, index, ids):
    values = [{"id": doc_id, "index": index, "data": {"file": {"path": f"/etc/{doc_id}"}}} for doc_id in ids]
    _ok(client.post_stateful(build_session(default_start(agent_id, cluster, module="fim"),
                                           {"sync_data": {"values": values}}), agent_id=agent_id))


def test_clean_single_index(client, cluster, indexer, agent_id):
    other_agent = f"{int(agent_id) + 1:03d}"
    _seed(client, cluster, agent_id, FILES, ["f1", "f2"])
    _seed(client, cluster, other_agent, FILES, ["f9"])
    indexer.refresh()  # delete-by-query acts on the search view

    body = _ok(client.post_stateful(build_session(default_start(agent_id, cluster, module="fim"),
                                                  {"cleans": [FILES]}), agent_id=agent_id))
    assert body == {"status": "ok"}

    # The clean is agent-scoped: the sibling agent's documents survive.
    assert indexer.wait_for_docs(agent_id, 0) == []
    assert len(indexer.agent_docs(other_agent)) == 1


def test_clean_multiple_indices_in_one_session(client, cluster, indexer, agent_id):
    _seed(client, cluster, agent_id, FILES, ["f1"])
    _seed(client, cluster, agent_id, KEYS, ["k1"])
    _seed(client, cluster, agent_id, SYSTEM, ["os1"])
    indexer.refresh()

    # FIM clears files and registry keys together; the system index is untouched.
    body = _ok(client.post_stateful(build_session(default_start(agent_id, cluster, module="fim"),
                                                  {"cleans": [FILES, KEYS, FILES]}),  # repeats dedupe
                                    agent_id=agent_id))
    assert body == {"status": "ok"}

    docs = indexer.wait_for_docs(agent_id, 1)
    assert docs[0]["_index"] == SYSTEM


def test_clean_of_forbidden_indices_is_a_noop(client, cluster, indexer, agent_id):
    _seed(client, cluster, agent_id, FILES, ["keepme"])

    body = _ok(client.post_stateful(build_session(default_start(agent_id, cluster),
                                                  {"cleans": ["not-wazuh-states", "another-bogus"]}),
                                    agent_id=agent_id))
    assert body == {"status": "ok", "noop": True}
    assert len(indexer.agent_docs(agent_id)) == 1  # nothing was deleted


def test_full_resync_is_cleans_then_delta(client, cluster, indexer, agent_id):
    """D19: there is no ModuleFull -- a full resync is TWO ordinary requests on
    the same shard (FIFO), and the final state is exactly the new dataset."""
    _seed(client, cluster, agent_id, FILES, ["old-1", "old-2", "old-3"])
    indexer.refresh()

    _ok(client.post_stateful(build_session(default_start(agent_id, cluster, module="fim"),
                                           {"cleans": [FILES]}), agent_id=agent_id))
    _seed(client, cluster, agent_id, FILES, ["new-1", "new-2"])

    docs = indexer.wait_for_docs(agent_id, 2)
    ids = sorted(document["_id"].split("_", 2)[2] for document in docs)
    assert ids == ["new-1", "new-2"]
