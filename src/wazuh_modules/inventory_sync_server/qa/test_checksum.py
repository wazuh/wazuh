"""ModuleCheck: REAL integrity verification coverage.

The legacy suite's module_check scenarios used the wrong mode value and their
assertions were never evaluated -- ModuleCheck had zero integration coverage.
These tests compute the aggregate the same way the server does (the contract):
page the agent's documents ordered by checksum.hash.sha1 ascending, concatenate
those checksums, SHA-1 the concatenation, lowercase hex.
"""

import hashlib
import json

from helpers.session_builder import build_session, default_start

PACKAGES = "wazuh-states-inventory-packages"


def _ok(response):
    assert response.status == 200, response.body
    return json.loads(response.body)


def _aggregate(checksums):
    return hashlib.sha1("".join(sorted(checksums)).encode()).hexdigest()


def _seed_with_checksums(client, cluster, agent_id, count):
    """One delta session of `count` documents, each carrying checksum.hash.sha1."""
    checksums = [hashlib.sha1(f"{agent_id}-doc-{i}".encode()).hexdigest() for i in range(count)]
    values = [{"id": f"doc-{i}", "index": PACKAGES,
               "data": {"package": {"name": f"pkg-{i}"}, "checksum": {"hash": {"sha1": checksums[i]}}}}
              for i in range(count)]
    session = build_session(default_start(agent_id, cluster), {"sync_data": {"values": values}})
    _ok(client.post_stateful(session, agent_id=agent_id, timeout=180))
    return checksums


def _check(client, cluster, agent_id, claimed):
    session = build_session(default_start(agent_id, cluster, mode="check"),
                            {"checksum": {"index": PACKAGES, "checksum": claimed}})
    return client.post_stateful(session, agent_id=agent_id)


def test_checksum_match(client, cluster, indexer, agent_id):
    checksums = _seed_with_checksums(client, cluster, agent_id, 5)
    indexer.refresh()  # the check searches; make the flushed docs visible NOW

    response = _check(client, cluster, agent_id, _aggregate(checksums))
    assert response.status == 200, response.body
    assert json.loads(response.body) == {"status": "ok"}


def test_checksum_mismatch_is_409(client, cluster, indexer, agent_id):
    _seed_with_checksums(client, cluster, agent_id, 5)
    indexer.refresh()

    response = _check(client, cluster, agent_id, "0" * 40)
    assert response.status == 409, response.body
    assert json.loads(response.body) == {"status": "checksum_mismatch"}


def test_checksum_scopes_to_the_agent(client, cluster, indexer, agent_id):
    """Another agent's documents in the same index must not pollute the aggregate."""
    other_agent = f"{int(agent_id) + 1:03d}"
    mine = _seed_with_checksums(client, cluster, agent_id, 3)
    _seed_with_checksums(client, cluster, other_agent, 4)
    indexer.refresh()

    assert _check(client, cluster, agent_id, _aggregate(mine)).status == 200


def test_checksum_paginates_past_one_search_page(client, cluster, indexer, agent_id):
    """The server pages by search_after in batches of 1000; 1100 documents force
    a second page. This is the coverage hole the legacy suite never closed."""
    checksums = _seed_with_checksums(client, cluster, agent_id, 1100)
    indexer.refresh()
    assert len(indexer.wait_for_docs(agent_id, 1100, index=PACKAGES, timeout=30)) == 1100

    response = _check(client, cluster, agent_id, _aggregate(checksums))
    assert response.status == 200, response.body


def test_checksum_over_an_empty_set(client, cluster, indexer, agent_id):
    """No documents for THIS agent: the aggregate is SHA-1 of the empty string
    -- an agent that just cleaned can verify emptiness. (The index itself
    exists, as it does for any agent that ever synced.)"""
    other_agent = f"{int(agent_id) + 1:03d}"
    _seed_with_checksums(client, cluster, other_agent, 1)
    indexer.refresh()

    response = _check(client, cluster, agent_id, hashlib.sha1(b"").hexdigest())
    assert response.status == 200, response.body


def test_check_after_delta_orders_fifo(client, cluster, indexer, agent_id):
    """Delta then check of the SAME agent in quick succession: the shard FIFO
    plus the batch cut guarantee the check sees the delta's documents."""
    checksums = _seed_with_checksums(client, cluster, agent_id, 2)
    indexer.refresh()

    response = _check(client, cluster, agent_id, _aggregate(checksums))
    assert response.status == 200, response.body
