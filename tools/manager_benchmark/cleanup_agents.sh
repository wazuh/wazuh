#!/usr/bin/env bash
set -euo pipefail
# ---------------------------------------------------------------------------
# cleanup_agents.sh — Remove benchmark agents from the manager.
#
# The sender names every simulated agent "bench-<fleet>-NNNN", so this deletes
# only agents whose name starts with "bench-" (q=name~bench-) — real agents are
# never touched. Used by run_benchmark.sh before each agent-mode run to avoid
# bench-* accumulation, and optionally after (--cleanup-after).
#
# Usage:
#   ./cleanup_agents.sh                 # delete bench-* agents
#   ./cleanup_agents.sh --all           # delete ALL agents except 000 (manager)
# Environment: WAZUH_API_URL WAZUH_API_USER WAZUH_API_PASS
# ---------------------------------------------------------------------------

API_URL="${WAZUH_API_URL:-https://localhost:55000}"
API_USER="${WAZUH_API_USER:-wazuh}"
API_PASS="${WAZUH_API_PASS:-wazuh}"
PYTHON="${PYTHON:-python3}"
REMOVE_ALL=false

[[ "${1:-}" == "--all" ]] && REMOVE_ALL=true

TOKEN=$(curl -s -k -X POST "${API_URL}/security/user/authenticate" \
    -u "${API_USER}:${API_PASS}" | "$PYTHON" -c 'import sys,json; print(json.load(sys.stdin)["data"]["token"])' 2>/dev/null || true)

if [[ -z "$TOKEN" ]]; then
    echo "Error: could not authenticate with the Wazuh API at ${API_URL}" >&2
    exit 1
fi

if $REMOVE_ALL; then
    echo "Fetching all agents..."
    AGENTS_JSON=$(curl -s -k "${API_URL}/agents?limit=100000&select=id,name&offset=0" \
        -H "Authorization: Bearer ${TOKEN}")
else
    echo "Fetching benchmark agents (name starts with 'bench-')..."
    AGENTS_JSON=$(curl -s -k "${API_URL}/agents?limit=100000&select=id,name&q=name~bench-&offset=0" \
        -H "Authorization: Bearer ${TOKEN}")
fi

AGENT_IDS=$(echo "$AGENTS_JSON" | "$PYTHON" -c '
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

NUM_AGENTS=$(echo "$AGENT_IDS" | tr ',' '\n' | wc -l)
echo "Found $NUM_AGENTS agent(s) to remove."

RESULT=$(curl -s -k -X DELETE "${API_URL}/agents?agents_list=${AGENT_IDS}&status=all&older_than=0s" \
    -H "Authorization: Bearer ${TOKEN}")

echo "$RESULT" | "$PYTHON" -c '
import sys, json
data = json.load(sys.stdin)
d = data.get("data", {})
deleted = d.get("total_affected_items", 0)
failed = d.get("total_failed_items", 0)
print("Deleted: {}, Failed: {}".format(deleted, failed))
'
echo "Done."
