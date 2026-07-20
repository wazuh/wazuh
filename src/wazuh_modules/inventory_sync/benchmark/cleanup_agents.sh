#!/usr/bin/env bash
set -euo pipefail
# ---------------------------------------------------------------------------
# cleanup_agents.sh — Remove all benchmark agents from the manager.
#
# Deletes agents whose name starts with "bench-" via the Wazuh API,
# keeping real agents (like agent 001) intact.
#
# Usage:
#   ./cleanup_agents.sh
#   ./cleanup_agents.sh --all   # Remove ALL agents except 000 (manager)
# ---------------------------------------------------------------------------

API_URL="https://localhost:55000"
API_USER="${WAZUH_API_USER:-wazuh}"
API_PASS="${WAZUH_API_PASS:-wazuh}"
REMOVE_ALL=false

if [[ "${1:-}" == "--all" ]]; then
    REMOVE_ALL=true
fi

# Get auth token
TOKEN=$(curl -s -k -X POST "${API_URL}/security/user/authenticate" \
    -u "${API_USER}:${API_PASS}" | python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["token"])')

if [[ -z "$TOKEN" ]]; then
    echo "Error: Could not authenticate with API"
    exit 1
fi

# Get list of bench agents
if $REMOVE_ALL; then
    echo "Fetching all agents..."
    AGENTS_JSON=$(curl -s -k "${API_URL}/agents?limit=500&select=id,name&offset=0" \
        -H "Authorization: Bearer ${TOKEN}")
else
    echo "Fetching benchmark agents (name starts with 'bench-')..."
    AGENTS_JSON=$(curl -s -k "${API_URL}/agents?limit=500&select=id,name&q=name~bench-&offset=0" \
        -H "Authorization: Bearer ${TOKEN}")
fi

# Extract agent IDs (skip 000)
AGENT_IDS=$(echo "$AGENTS_JSON" | python3 -c '
import sys, json
data = json.load(sys.stdin)
items = data.get("data", {}).get("affected_items", [])
ids = [item["id"] for item in items if item["id"] != "000"]
print(",".join(ids))
')

if [[ -z "$AGENT_IDS" ]]; then
    echo "No agents to remove."
    exit 0
fi

# Count
NUM_AGENTS=$(echo "$AGENT_IDS" | tr ',' '\n' | wc -l)
echo "Found $NUM_AGENTS agent(s) to remove."

# Delete agents
RESULT=$(curl -s -k -X DELETE "${API_URL}/agents?agents_list=${AGENT_IDS}&status=all&older_than=0s" \
    -H "Authorization: Bearer ${TOKEN}")

DELETED=$(echo "$RESULT" | python3 -c '
import sys, json
data = json.load(sys.stdin)
total = data.get("data", {}).get("total_affected_items", 0)
errors = data.get("data", {}).get("total_failed_items", 0)
print(f"Deleted: {total}, Failed: {errors}")
')

echo "$DELETED"
echo "Done."
