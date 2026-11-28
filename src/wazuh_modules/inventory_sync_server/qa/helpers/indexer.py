"""Thin OpenSearch client for state-index assertions."""

import time

import requests

STATES_PATTERN = "wazuh-states-*"
AGENT_CONFIG_INDEX = "wazuh-agent-config"
AGENT_STATS_INDEX = "wazuh-agent-stats"

# Everything a whole-agent deletion has to reach, whichever half reaches it -- the union of
# AGENT_DELETION_SCOPE_BY_QUERY and AGENT_DELETION_SCOPE_BY_ID in src/sync/stateIndexAllowlist.hpp.
# The states pattern is deleted by query through the `inventory` bucket's connector; the two wazuh-agent-*
# documents by document id, one Group on the `agent-state` bucket that writes them. From the indexer's
# side the outcome is the same, which is why this stays one tuple.
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

    def index_exists(self, index):
        return requests.head(f"{self.base_url}/{index}", timeout=10).status_code == 200

    def put_doc(self, index, doc_id, document):
        """Writes one document directly, refreshed, bypassing the server (index auto-created if absent)."""
        response = requests.put(f"{self.base_url}/{index}/_doc/{doc_id}?refresh=true",
                                json=document, timeout=10)
        response.raise_for_status()

    def get(self, index, doc_id):
        response = requests.get(f"{self.base_url}/{index}/_doc/{doc_id}", timeout=10)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

    def wait_for_docs(self, agent_id, count, index=STATES_PATTERN, timeout=10):
        """Poll until the agent has exactly `count` docs.

        For what is written AFTER the server answers -- a /config or /stats report, which the
        `agent-state` bucket sends on its own age bound -- and for the index refresh after it. The
        deletion route needs no such wait: it answers at COMPLETION."""
        deadline = time.monotonic() + timeout
        docs = None
        unavailable = None
        while time.monotonic() < deadline:
            try:
                docs = self.agent_docs(agent_id, index=index)
            except requests.HTTPError as error:
                # The first write of a test auto-creates an index the previous test deleted, and a
                # search that lands while its primary shard is still being allocated answers 503.
                # Poll again: a failed search says nothing about the count, not even about zero.
                if error.response is None or error.response.status_code != 503:
                    raise
                unavailable = error
                time.sleep(0.2)
                continue
            if len(docs) == count:
                return docs
            time.sleep(0.2)
        if docs is None and unavailable is not None:
            raise unavailable
        return docs if docs is not None else []
