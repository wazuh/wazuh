#!/bin/bash
# #36101 spike performance matrix: pods x rate cells, each driven by
# sample-perf.sh. Skips cells above MAX_TOTAL_LPS. Stops dashboard/indexer
# noise sources first. Summary lines land in <evidence>/matrix-summary.txt.
set -uo pipefail

EVIDENCE=${1:-"$HOME/Dev/jr0me/wazuh-36101-spike/evidence/perf"}
DURATION=${DURATION:-600}
MAX_TOTAL_LPS=${MAX_TOTAL_LPS:-3000}
PODS_AXIS=(${PODS_AXIS:-10 30 60 110})
RATE_AXIS=(${RATE_AXIS:-1 10 50})
REPO_ROOT=$(git rev-parse --show-toplevel)
QA_DIR="$REPO_ROOT/src/wazuh_modules/container_connector/qa/kind"

mkdir -p "$EVIDENCE"
SUMMARY="$EVIDENCE/matrix-summary.txt"
: > "$SUMMARY"

echo "==> reducing manager-side noise (dashboard stopped; indexer kept for engine health)"
docker exec wazuh-server bash -c 'systemctl stop wazuh-dashboard 2>/dev/null; true'

echo "==> stopping the testenv host agent (manager load hygiene)"
docker exec wazuh-agent bash -c 'systemctl stop wazuh-agent 2>/dev/null; /var/ossec/bin/wazuh-control stop 2>/dev/null; true'

for pods in "${PODS_AXIS[@]}"; do
    for rate in "${RATE_AXIS[@]}"; do
        total=$((pods * rate))
        if [ "$total" -gt "$MAX_TOTAL_LPS" ]; then
            echo "skip p${pods}-r${rate} (total ${total} l/s > ${MAX_TOTAL_LPS})" | tee -a "$SUMMARY"
            continue
        fi
        echo "==> cell p${pods}-r${rate} (total ${total} l/s, ${DURATION}s)"
        # truncate dated channel files between cells to bound verifier input
        docker exec wazuh-server bash -c \
          'find /var/wazuh-manager/logs/standard-wazuh-events-v5 -mindepth 2 -name "*.json" -exec truncate -s 0 {} +; \
           find /var/wazuh-manager/logs/standard-wazuh-events-v5 -mindepth 2 -name "*.json.gz" -delete' 2>/dev/null
        bash "$QA_DIR/scripts/sample-perf.sh" "$pods" "$rate" "$DURATION" "$EVIDENCE" \
            | tee -a "$SUMMARY" | tail -1
    done
done

echo "==> scaling generators down"
kubectl -n loadtest delete deploy/seqgen --ignore-not-found >/dev/null 2>&1

echo "==> matrix done: $SUMMARY"
cat "$SUMMARY"
