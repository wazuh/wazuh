"""Thin OpenSearch client for state-index assertions."""

import time

import requests

STATES_PATTERN = "wazuh-states-*"
AGENT_CONFIG_INDEX = "wazuh-agent-config"
AGENT_STATS_INDEX = "wazuh-agent-stats"

# Everything a whole-agent deletion has to reach, whichever half reaches it -- the union of
# AGENT_DELETION_SCOPE_BY_QUERY and AGENT_DELETION_SCOPE_BY_ID in src/sync/stateIndexAllowlist.hpp.
# The states pattern is deleted by query on the sync connector; the two wazuh-agent-* documents by
# document id on the async one that writes them. From the indexer's side the outcome is the same,
# which is why this stays one tuple.
DELETION_SCOPE = (STATES_PATTERN, AGENT_CONFIG_INDEX, AGENT_STATS_INDEX)


class Indexer:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    def available(self):
        try:
            return requests.get(self.base_url, timeout=5).status_code == 200
        except requests.RequestException:
            return False

    def refresh(self, pattern=STATES_PATTERN):
        # Make everything the server flushed searchable NOW (the bulk API's own
        # refresh cycle is 1 s and the suite should not sleep for it).
        requests.post(f"{self.base_url}/{pattern}/_refresh", timeout=10)

    def delete_states(self):
        """Wipe every index a test may have written, between tests (missing ones are fine)."""
        for pattern in DELETION_SCOPE:
            requests.delete(f"{self.base_url}/{pattern}", timeout=10)

    def search(self, index=STATES_PATTERN, query=None, size=100):
        body = {"size": size, "query": query or {"match_all": {}}}
        response = requests.post(f"{self.base_url}/{index}/_search",
                                 json=body,
                                 headers={"Content-Type": "application/json"},
                                 timeout=10)
        if response.status_code == 404:  # the index was never created
            return []
        response.raise_for_status()
        return response.json()["hits"]["hits"]

    def agent_docs(self, agent_id, index=STATES_PATTERN, size=2000):
        """Every state document of one agent: [{_id, _index, _source}, ...]."""
        self.refresh(index)
        return self.search(index=index, query={"term": {"wazuh.agent.id": agent_id}}, size=size)

    def agent_docs_in_scope(self, agent_id):
        """Every document of one agent across the whole deletion scope, index by index."""
        return {pattern: self.agent_docs(agent_id, index=pattern) for pattern in DELETION_SCOPE}

    def get(self, index, doc_id):
        response = requests.get(f"{self.base_url}/{index}/_doc/{doc_id}", timeout=10)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

    def wait_for_empty_scope(self, agent_id, timeout=20):
        """Poll until the agent has no documents left anywhere in the deletion scope.

        Same reason as wait_for_docs: the purge runs after the 200, so the scope empties
        asynchronously. Returns the last snapshot, so a failure can name what survived."""
        deadline = time.monotonic() + timeout
        scope = {}
        while time.monotonic() < deadline:
            scope = self.agent_docs_in_scope(agent_id)
            if all(not docs for docs in scope.values()):
                return scope
            time.sleep(0.2)
        return scope

    def wait_for_docs(self, agent_id, count, index=STATES_PATTERN, timeout=10):
        """Poll until the agent has exactly `count` docs.

        The deletion route answers at ADMISSION, so a 200 only promises the purge is queued:
        this loop is what waits for the purge itself, plus the index refresh after it."""
        deadline = time.monotonic() + timeout
        docs = []
        while time.monotonic() < deadline:
            docs = self.agent_docs(agent_id, index=index)
            if len(docs) == count:
                return docs
            time.sleep(0.2)
        return docs
