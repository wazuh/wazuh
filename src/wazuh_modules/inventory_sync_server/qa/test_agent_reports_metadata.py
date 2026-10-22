"""The agent's groups and host in POST /stats and POST /config.

Both reports carry the agent's groups and host in a root `agent` object; the server copies them into
`wazuh.agent.groups` and `wazuh.agent.host`, the shape the wazuh-states-* documents use, and leaves a
bad value empty instead of rejecting the report."""

import pytest

from helpers.indexer import AGENT_CONFIG_INDEX, AGENT_STATS_INDEX

# Both reports are written by the ASYNC connector, which answers 200 before the document reaches the
# indexer; see test_delete_agent.py.
ASYNC_WRITE_TIMEOUT = 30

AGENT = {
    "id": "999",
    "name": "web-01",
    "groups": ["default", "linux"],
    "host": {
        "architecture": "x86_64",
        "hostname": "web-01",
        "os": {"name": "Ubuntu", "platform": "ubuntu", "type": "linux", "version": "24.04"},
    },
}

REPORTS = [
    pytest.param("post_stats", AGENT_STATS_INDEX, {"agent": {"uptime": 1}}, id="stats"),
    pytest.param("post_config", AGENT_CONFIG_INDEX, {"agent": {"name": "a"}}, id="config"),
]


def _indexed_agent(client, indexer, post, index, body, agent_id):
    response = getattr(client, post)(body, agent_id=agent_id)
    assert response.status == 200, response.body
    docs = indexer.wait_for_docs(agent_id, 1, index=index, timeout=ASYNC_WRITE_TIMEOUT)
    assert len(docs) == 1, f"agent {agent_id} has {len(docs)} documents in {index}"
    return docs[0]["_source"]["wazuh"]["agent"]


@pytest.mark.parametrize("post,index,modules", REPORTS)
def test_groups_and_host_are_indexed(client, indexer, agent_id, post, index, modules):
    agent = _indexed_agent(client, indexer, post, index, {"modules": modules, "agent": AGENT}, agent_id)

    assert agent["id"] == agent_id
    assert agent["groups"] == AGENT["groups"]
    assert agent["host"] == AGENT["host"]
    assert "name" not in agent


@pytest.mark.parametrize("post,index,modules", REPORTS)
def test_a_report_without_metadata_has_no_groups_or_host(client, indexer, agent_id, post, index, modules):
    agent = _indexed_agent(client, indexer, post, index, {"modules": modules}, agent_id)

    assert "groups" not in agent
    assert "host" not in agent


@pytest.mark.parametrize("post,index,modules", REPORTS)
def test_bad_metadata_is_left_empty_not_rejected(client, indexer, agent_id, post, index, modules):
    bad = {"groups": ["default", ""], "host": {"hostname": 42, "architecture": "x86_64"}}
    agent = _indexed_agent(client, indexer, post, index, {"modules": modules, "agent": bad}, agent_id)

    assert agent["groups"] == []
    assert agent["host"]["hostname"] == ""
    assert agent["host"]["architecture"] == "x86_64"
    assert agent["host"]["os"] == {"name": "", "platform": "", "type": "", "version": ""}
