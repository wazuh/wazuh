"""A state write must not be lost when a group update runs over the same documents at the same time.

A versioned sync value is applied with a scripted `update`: the indexer reads the document, runs the version-guarded
script and writes the result back only if the document did not change meanwhile. A group (or metadata) session is an
`_update_by_query` over every document of the agent. When that by-query rewrites a document between the update's read
and its write, the update item is answered 409 inside an HTTP 200 bulk and its data is dropped. The server must not
answer 200 for a session whose data was not stored, and the data must end up in the index.

This is a stress test: the overlap is timing dependent, so it repeats many rounds over many documents.
Tune with QA_RACE_ROUNDS (default 20) and QA_RACE_DOCS (default 3000).
"""

import os
import threading

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


def _sync_session(cluster, agent_id, checksum, version):
    return build_session(default_start(agent_id, cluster), {"sync_data": {"values": _values(checksum, version)}})


def _groups_session(cluster, agent_id, version, groups):
    start = default_start(agent_id, cluster, mode="group_delta", indices=[FIM], global_version=version, groups=groups)
    return build_session(start, None)


def _stale(indexer, agent_id, checksum):
    docs = indexer.agent_docs(agent_id, index=FIM, size=DOCS + 100)
    assert len(docs) == DOCS, f"expected {DOCS} documents, found {len(docs)}"
    return [d["_id"] for d in docs if d["_source"]["checksum"]["hash"]["sha1"] != checksum]


def test_sync_is_not_lost_when_a_group_update_runs_at_the_same_time(client, cluster, indexer, agent_id):
    seed = client.post_stateful(_sync_session(cluster, agent_id, "round-0", BASE_VERSION), agent_id=agent_id)
    assert seed.status == 200, seed.body
    assert _stale(indexer, agent_id, "round-0") == []

    lost = {}
    for rnd in range(1, ROUNDS + 1):
        version = BASE_VERSION + rnd
        checksum = f"round-{rnd}"
        sync = _sync_session(cluster, agent_id, checksum, version)
        # Same version as the sync, so a stale document can only come from a lost concurrent write and not from the
        # version guard legitimately skipping an older update.
        groups = _groups_session(cluster, agent_id, version, [f"g{rnd % 2}", "extra"])

        responses = {}
        barrier = threading.Barrier(2)

        def send(name, session):
            barrier.wait()
            responses[name] = client.post_stateful(session, agent_id=agent_id, timeout=120)

        threads = [threading.Thread(target=send, args=("sync", sync)),
                   threading.Thread(target=send, args=("groups", groups))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert responses["groups"].status == 200, responses["groups"].body
        # A rejected write may be reported to the caller (so it is sent again) or retried until it lands. What is not
        # allowed is a 200 for a session whose data is missing from the index.
        stale = _stale(indexer, agent_id, checksum)
        if stale and responses["sync"].status == 200:
            lost[rnd] = len(stale)
        elif responses["sync"].status != 200:
            # The server reported the failure: the agent would resend. Re-apply to continue with a clean round.
            retry = client.post_stateful(_sync_session(cluster, agent_id, checksum, version), agent_id=agent_id)
            assert retry.status == 200, retry.body

    assert not lost, (f"the server answered 200 but {sum(lost.values())} documents did not get the new data "
                      f"(per round: {lost})")
