"""Whole-agent deletion: POST /_internal/agents/delete, the Task Manager dispatcher's route.

Answered at COMPLETION -- the 200 means the delete-by-query ran AND flushed -- so unlike every
other suite here these tests never poll for the by-query half. agent_docs() refreshes and
searches once, and that absence of a wait IS the assertion."""

import json

import pytest

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
    otherwise pass for the wrong reason: nothing was there to delete.

    Waiting here also means the report is no longer IN FLIGHT when the deletion runs, so a test that
    waits first is testing the deletion against documents already in the indexer.
    test_a_report_in_flight_does_not_survive_the_deletion below deliberately does not wait -- that is
    the case that used to leave a document behind."""
    for index in (AGENT_CONFIG_INDEX, AGENT_STATS_INDEX):
        docs = indexer.wait_for_docs(agent_id, 1, index=index, timeout=ASYNC_WRITE_TIMEOUT)
        assert docs, f"agent {agent_id} has no document in {index} after {ASYNC_WRITE_TIMEOUT}s"


def test_delete_agent_wipes_only_that_agent(client, cluster, indexer, agent_id):
    survivor = f"{int(agent_id) + 1:03d}"
    _seed(client, cluster, agent_id)
    _seed(client, cluster, survivor)
    indexer.refresh()  # delete-by-query acts on the search view

    response = client.delete_agent({"agent_id": agent_id})
    assert response.status == 200, response.body
    # Answered at COMPLETION, so the purge has already run and flushed when this arrives.
    assert json.loads(response.body) == {"status": "ok"}

    # No polling anywhere in this file, and that is the assertion: agent_docs() refreshes and
    # searches once, so a purge that were still queued would be caught here.
    assert indexer.agent_docs(agent_id) == [], \
        "the response arrived before the purge: `completed` would not mean purged"
    assert len(indexer.agent_docs(survivor)) == 2


def test_delete_agent_wipes_config_and_stats_too(client, cluster, indexer, agent_id):
    """The regression this endpoint had: `wazuh-agent-config` and `wazuh-agent-stats`
    live outside `wazuh-states-*`, so the states pattern alone left them behind -- and
    with the agent gone from client.keys nothing ever overwrote them again.

    These two are no longer covered by the deletion's by-query pass at all: they are deleted by
    document id on the async connector that writes them (AGENT_DELETION_SCOPE_BY_ID). That half stays
    fire-and-forget -- the queue it rides is what orders it behind a report already accepted, and it
    exposes nothing to wait on -- so unlike the by-query half it IS awaited here."""
    survivor = f"{int(agent_id) + 1:03d}"
    _seed(client, cluster, agent_id)
    _seed_config_and_stats(client, agent_id)
    _seed_config_and_stats(client, survivor)

    _await_config_and_stats(indexer, agent_id)
    _await_config_and_stats(indexer, survivor)
    indexer.refresh()  # the wazuh-states-* seeds too: the server does not refresh before deleting

    assert client.delete_agent({"agent_id": agent_id}).status == 200

    for pattern, docs in indexer.wait_for_empty_scope(agent_id).items():
        assert docs == [], f"agent {agent_id} still has documents in {pattern}"

    # Scoped: the deletion is per agent, not a wipe of the shared indices.
    assert len(indexer.agent_docs(survivor, index=AGENT_CONFIG_INDEX)) == 1
    assert len(indexer.agent_docs(survivor, index=AGENT_STATS_INDEX)) == 1


@pytest.mark.skip(reason="KNOWN LIMITATION, not yet fixed: the deletion does not refresh before its "
                         "delete-by-query, because `_refresh` needs `indices:admin/refresh` and the "
                         "manager's indexer role does not grant it. See the follow-up to restore it.")
def test_delete_sees_documents_written_inside_the_refresh_interval(client, cluster, indexer, agent_id):
    """No indexer.refresh() here, deliberately -- this is the window the deletion leaves open.

    A delete-by-query is a SEARCH, and the state indices refresh on their own interval; the deletion
    runs behind the agent's last session, so documents that session wrote inside that interval are
    invisible to the query. The deletion answers 200 having matched nothing and, with the agent gone
    from client.keys, nothing ever overwrites them.

    Refreshing each index first closed this, but it made every deletion fail with `403` on a manager
    whose indexer role lacks `indices:admin/refresh`, so the refresh was removed. Unskip once the
    privilege is granted and the refresh is restored; repeating the deletion is the recovery
    meanwhile, and it is idempotent.

    Only the state documents are seeded: they are written synchronously, so the session's 200 means
    they ARE in the indexer, just not searchable yet -- which is exactly the window under test."""
    _seed(client, cluster, agent_id)

    assert client.delete_agent({"agent_id": agent_id}).status == 200

    assert indexer.agent_docs(agent_id) == [], \
        "the deletion missed state documents that were flushed but not yet refreshed"


def test_deleting_an_absent_agent_succeeds(client, agent_id):
    """404-as-success: repeating a delete is harmless -- a delete-by-query against an index that was
    never created counts as success in the connector. It is what makes the dispatcher's retries free,
    and this task type has no attempt budget, so it retries until it succeeds."""
    assert client.delete_agent({"agent_id": agent_id}).status == 200
    assert client.delete_agent({"agent_id": agent_id}).status == 200


def test_the_agent_id_comes_from_the_body(client, cluster, indexer, agent_id):
    """No X-Wazuh-Agent-Id anywhere in this request. The dispatcher sends a task row's payload as the
    body and nothing else, so the body is the only channel the id can arrive through."""
    survivor = f"{int(agent_id) + 1:03d}"
    _seed(client, cluster, agent_id)
    _seed(client, cluster, survivor)
    indexer.refresh()

    assert client.delete_agent({"agent_id": agent_id}).status == 200
    assert indexer.agent_docs(agent_id) == []
    assert len(indexer.agent_docs(survivor)) == 2, "the deletion is per agent, not a wipe"


def test_a_body_that_names_no_agent_is_400(client):
    for body in (b"", b"not json", b"[]", {}, {"agent_id": None}, {"agent_id": "not-numeric"}):
        assert client.delete_agent(body).status == 400, f"body={body!r}"


def test_the_number_spelling_of_an_agent_id_is_accepted(client, cluster, indexer, agent_id):
    """A producer that writes 7 rather than "7" is tolerated on purpose: this task type's 4xx comes
    back to the dispatcher as retryable, so rejecting it would re-queue the deletion forever."""
    _seed(client, cluster, agent_id)
    indexer.refresh()

    assert client.delete_agent({"agent_id": int(agent_id)}).status == 200
    assert indexer.agent_docs(agent_id) == []


def test_delete_orders_after_the_same_agents_session(client, cluster, indexer, agent_id):
    """The deletion rides the agent's own shard: a session, then the delete,
    arrive in order -- the final state is 'deleted', never 'resurrected'."""
    _seed(client, cluster, agent_id)
    _seed(client, cluster, agent_id)  # a second in-flight-ish write
    indexer.refresh()

    assert client.delete_agent({"agent_id": agent_id}).status == 200
    assert indexer.agent_docs(agent_id) == []


def test_a_report_in_flight_does_not_survive_the_deletion(client, cluster, indexer, agent_id):
    """The reported bug, and the reason the deletion has a by-id half.

    `/config` and `/stats` hand their document to the ASYNC connector, which accumulates and pushes
    in batches by design (`inventory_sync_server_indexer_async_flush_interval_seconds`, 20 s by
    default; 1 s in this suite). A report still in that queue when the deletion ran used to land
    AFTER it and recreate the document -- for good, since with the agent gone from client.keys
    nothing overwrites it and nothing re-runs a deletion.

    So the deletion queues a by-id delete for each of those two documents on that SAME queue: it is
    FIFO, so the report is applied first and the delete right behind it. No wait here, deliberately
    -- the reports are still in flight when the deletion is sent, which is exactly the case that
    used to fail.
    """
    survivor = f"{int(agent_id) + 1:03d}"

    _seed_config_and_stats(client, agent_id)     # deliberately NOT awaited: still in the async queue
    assert client.delete_agent({"agent_id": agent_id}).status == 200

    # The barrier, and the reason this test cannot pass for the wrong reason: a report queued AFTER
    # the deletion. Its document appearing proves the queue has drained past everything queued
    # before it -- this agent's two reports AND the two deletes behind them. Without it, "the report
    # has not been pushed yet" and "the report was deleted" would look identical.
    assert client.post_config({"modules": {"agent": {"name": "b"}}}, agent_id=survivor).status == 200
    assert indexer.wait_for_docs(survivor, 1, index=AGENT_CONFIG_INDEX, timeout=ASYNC_WRITE_TIMEOUT), \
        f"the async queue never drained: agent {survivor} has no document after {ASYNC_WRITE_TIMEOUT}s"

    for index in (AGENT_CONFIG_INDEX, AGENT_STATS_INDEX):
        assert indexer.agent_docs(agent_id, index=index) == [], \
            f"a report in flight at deletion time resurrected agent {agent_id} in {index}"
