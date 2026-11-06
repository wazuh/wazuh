"""A state write must not be lost when a group or metadata update of the same agent is applied by another instance.

A versioned sync value is applied with a scripted `update`: the indexer reads the document, runs the version-guarded
script and writes the result back with the seq_no it read. A group or a metadata session is an `_update_by_query` over
every document of the agent. When that by-query rewrites a document between the update's read and its write, the
indexer re-reads and re-runs the script (`retry_on_conflict`); an update that still conflicts is answered 409 inside
an HTTP 200 bulk and its data is dropped, which the server must report as a failure. The server must not answer 200
for a session whose data was not stored, and the data must end up in the index.

One instance never overlaps the two: a worker applies the sessions of an agent in order and flushes the open bulk
before it runs a group or metadata update. Two instances (two manager nodes behind a balancer, which can send an
agent's consecutive requests to different nodes) share nothing but the indexer, so nothing orders them.

These are stress tests: the overlap is timing dependent, so they repeat many rounds over many documents.
Tune with QA_RACE_ROUNDS (default 20) and QA_RACE_DOCS (default 3000).
"""

import os
import threading

import pytest

from helpers.session_builder import build_session, default_start

FIM = "wazuh-states-fim-files"
ROUNDS = int(os.environ.get("QA_RACE_ROUNDS", "20"))
DOCS = int(os.environ.get("QA_RACE_DOCS", "3000"))
BASE_VERSION = 1000


def _values(checksum, version):
    return [
        {
            "id": f"file-{i}",
            "index": FIM,
            "version": version,
            "data": {"file": {"path": f"/data/file-{i}"}, "checksum": {"hash": {"sha1": checksum}}},
        }
        for i in range(DOCS)
    ]


def _agent_fields(kind, rnd):
    """The agent fields of one round, carried by both sessions as an agent that already knows them would send."""
    if kind == "groups":
        return {"groups": [f"g{rnd % 2}", "extra"]}
    return {"agentname": f"renamed-{rnd}", "hostname": f"host-{rnd}"}


def _sync_session(cluster, agent_id, checksum, version, **fields):
    return build_session(default_start(agent_id, cluster, **fields),
                         {"sync_data": {"values": _values(checksum, version)}})


def _agent_update_session(kind, cluster, agent_id, version, fields):
    mode = "group_delta" if kind == "groups" else "metadata_delta"
    start = default_start(agent_id, cluster, mode=mode, indices=[FIM], global_version=version, **fields)
    return build_session(start, None)


def _docs(indexer, agent_id):
    docs = indexer.agent_docs(agent_id, index=FIM, size=DOCS + 100)
    assert len(docs) == DOCS, f"expected {DOCS} documents, found {len(docs)}"
    return docs


def _stale(indexer, agent_id, checksum):
    return [d["_id"] for d in _docs(indexer, agent_id) if d["_source"]["checksum"]["hash"]["sha1"] != checksum]


def _assert_agent_fields(indexer, agent_id, fields):
    """Every document carries the round's agent fields, whichever of the two sessions wrote it last."""
    for doc in _docs(indexer, agent_id):
        agent = doc["_source"]["wazuh"]["agent"]
        if "groups" in fields:
            assert agent["groups"] == fields["groups"], f"{doc['_id']} groups: {agent['groups']}"
        else:
            assert agent["name"] == fields["agentname"], f"{doc['_id']} name: {agent['name']}"
            assert agent["host"]["hostname"] == fields["hostname"], f"{doc['_id']} hostname: {agent['host']}"


def _rounds(sync_client, update_client, cluster, indexer, agent_id, kind):
    """Sends a sync session and an agent update session of one agent at the same moment, round after round.

    Both sessions of a round carry the same agent fields (groups, or name and hostname), so after the round every
    document must hold them no matter which session wrote it last; a document with other values is a lost write.

    Returns {round: stale documents} for the rounds where the sync was answered 200 but its data is missing."""
    seed = sync_client.post_stateful(_sync_session(cluster, agent_id, "round-0", BASE_VERSION), agent_id=agent_id)
    assert seed.status == 200, seed.body
    assert _stale(indexer, agent_id, "round-0") == []

    lost = {}
    for rnd in range(1, ROUNDS + 1):
        version = BASE_VERSION + rnd
        checksum = f"round-{rnd}"
        fields = _agent_fields(kind, rnd)
        sync = _sync_session(cluster, agent_id, checksum, version, **fields)
        # Same version as the sync, so a stale document can only come from a lost concurrent write and not from the
        # version guard legitimately skipping an older update.
        update = _agent_update_session(kind, cluster, agent_id, version, fields)

        responses = {}
        barrier = threading.Barrier(2)

        def send(name, client, session):
            barrier.wait()
            responses[name] = client.post_stateful(session, agent_id=agent_id, timeout=120)

        threads = [threading.Thread(target=send, args=("sync", sync_client, sync)),
                   threading.Thread(target=send, args=("update", update_client, update))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert responses["update"].status == 200, responses["update"].body
        stale = _stale(indexer, agent_id, checksum)
        # A rejected write may be reported to the caller (so it is sent again) or retried until it lands. What is not
        # allowed is a 200 for a session whose data is missing from the index.
        if stale and responses["sync"].status == 200:
            lost[rnd] = len(stale)
        elif responses["sync"].status != 200:
            retry = sync_client.post_stateful(_sync_session(cluster, agent_id, checksum, version, **fields),
                                              agent_id=agent_id)
            assert retry.status == 200, retry.body
        _assert_agent_fields(indexer, agent_id, fields)
    return lost


@pytest.mark.parametrize("kind", ["groups", "metadata"])
def test_sync_is_not_lost_when_another_instance_applies_an_agent_update(kind, client, second_client, cluster, indexer,
                                                                        agent_id):
    lost = _rounds(client, second_client, cluster, indexer, agent_id, kind)
    assert not lost, (f"the sync was answered 200 but {sum(lost.values())} documents did not get the new data "
                      f"(per round: {lost})")


@pytest.mark.parametrize("kind", ["groups", "metadata"])
def test_one_instance_applies_the_sessions_of_an_agent_in_order(kind, client, cluster, indexer, agent_id):
    """Control: the same two sessions sent to ONE instance are ordered by its per-agent worker, nothing is lost."""
    lost = _rounds(client, client, cluster, indexer, agent_id, kind)
    assert not lost, f"{sum(lost.values())} documents lost on a single instance (per round: {lost})"
