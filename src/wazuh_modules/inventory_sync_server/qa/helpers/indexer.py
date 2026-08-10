"""Thin OpenSearch client for state-index assertions."""

import time

import requests

STATES_PATTERN = "wazuh-states-*"
AGENT_CONFIG_INDEX = "wazuh-agent-config"
AGENT_STATS_INDEX = "wazuh-agent-stats"

# Everything a whole-agent deletion has to reach -- mirrors AGENT_DELETION_SCOPE in
# src/sync/stateIndexAllowlist.hpp. The two wazuh-agent-* indices sit outside the
# states family, which is exactly why they used to survive the agent.
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

    def wait_for_docs(self, agent_id, count, index=STATES_PATTERN, timeout=10):
        """Poll until the agent has exactly `count` docs (a 200 means flushed,
        so this converges on the first refresh; the loop only absorbs it)."""
        deadline = time.monotonic() + timeout
        docs = []
        while time.monotonic() < deadline:
            docs = self.agent_docs(agent_id, index=index)
            if len(docs) == count:
                return docs
            time.sleep(0.2)
        return docs
