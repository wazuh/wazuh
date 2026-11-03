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
#
# The password has no default: a 5.x install generates the `wazuh` user's password
# and publishes it as WAZUH_MANAGER_API_PASSWORD in
# /etc/wazuh-manager/export/credentials.env (root-only). It is taken from, in order:
# WAZUH_API_PASS, WAZUH_MANAGER_API_PASSWORD, then that file when this user can
# read it (e.g. under sudo). Without one, or when the API refuses it, the script
# says why and exits 1 -- it never reports "nothing to remove" for a cleanup that
# did not run.
# ---------------------------------------------------------------------------

API_URL="${WAZUH_API_URL:-https://localhost:55000}"
API_USER="${WAZUH_API_USER:-wazuh}"
PUBLISHED_ENV="/etc/wazuh-manager/export/credentials.env"
PYTHON="${PYTHON:-python3}"
REMOVE_ALL=false

[[ "${1:-}" == "--all" ]] && REMOVE_ALL=true

API_PASS="${WAZUH_API_PASS:-${WAZUH_MANAGER_API_PASSWORD:-}}"
if [[ -z "$API_PASS" && -r "$PUBLISHED_ENV" ]]; then
    # Parse the line; the file is never sourced.
    API_PASS="$(sed -n 's/^WAZUH_MANAGER_API_PASSWORD=//p' "$PUBLISHED_ENV" | head -1)"
fi
if [[ -z "$API_PASS" ]]; then
    echo "Error: no Server API password for user '${API_USER}'." >&2
    echo "  Set WAZUH_API_PASS (or WAZUH_MANAGER_API_PASSWORD); the installed one is published in" >&2
    echo "  $PUBLISHED_ENV (root-only):" >&2
    echo "    export WAZUH_API_PASS=\"\$(sudo sed -n 's/^WAZUH_MANAGER_API_PASSWORD=//p' $PUBLISHED_ENV)\"" >&2
    exit 1
fi

AUTH_BODY="$(mktemp)"
trap 'rm -f "$AUTH_BODY"' EXIT
HTTP_CODE=$(curl -s -k -o "$AUTH_BODY" -w '%{http_code}' -X POST "${API_URL}/security/user/authenticate" \
    -u "${API_USER}:${API_PASS}" || true)
TOKEN=$("$PYTHON" -c 'import sys,json; print(json.load(sys.stdin)["data"]["token"])' <"$AUTH_BODY" 2>/dev/null || true)

if [[ -z "$TOKEN" ]]; then
    if [[ "$HTTP_CODE" == "000" || -z "$HTTP_CODE" ]]; then
        echo "Error: the Wazuh API at ${API_URL} is not reachable." >&2
    elif [[ "$HTTP_CODE" == "401" ]]; then
        echo "Error: the Wazuh API at ${API_URL} refused user '${API_USER}' (HTTP 401): wrong password?" >&2
        echo "  The installed password is WAZUH_MANAGER_API_PASSWORD in $PUBLISHED_ENV." >&2
    else
        echo "Error: could not authenticate with the Wazuh API at ${API_URL} (HTTP ${HTTP_CODE})." >&2
    fi
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
