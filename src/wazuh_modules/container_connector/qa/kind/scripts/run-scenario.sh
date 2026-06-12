#!/bin/bash
# Scenario driver for the #36101 spike. Usage:
#   run-scenario.sh S0|S1|S1b|S2|S3|S4 [evidence-dir]
#
# Requires: kind cluster up (kind-up.sh), agent DaemonSet running,
# wazuh-server container on the kind network with the engine file output on.
set -uo pipefail

SCENARIO=${1:?usage: run-scenario.sh S0|S1|S1b|S2|S3|S4 [evidence-dir]}
EVIDENCE_BASE=${2:-"$HOME/Dev/jr0me/wazuh-36101-spike/evidence/adhoc"}
REPO_ROOT=$(git rev-parse --show-toplevel)
QA_DIR="$REPO_ROOT/src/wazuh_modules/container_connector/qa/kind"
CHANNEL_DIR=/var/wazuh-manager/logs/standard-wazuh-events-v5
SETTLE=25   # seconds to let agent+engine pipelines drain after the window

RUN_DIR="$EVIDENCE_BASE/${SCENARIO}-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN_DIR"
exec > >(tee "$RUN_DIR/transcript.log") 2>&1

mgr() { docker exec wazuh-server bash -c "$*"; }

agent_pod() {
    kubectl -n wazuh get pod -l app=wazuh-agent \
        -o jsonpath='{.items[?(@.status.phase=="Running")].metadata.name}' | awk '{print $1}'
}

agent_exec() { kubectl -n wazuh exec "$(agent_pod)" -- "$@"; }

deploy_gen() { # name replicas rate pad
    SEQGEN_NAME=$1 SEQGEN_REPLICAS=$2 SEQGEN_RATE=$3 SEQGEN_PAD=$4 \
        envsubst < "$QA_DIR/manifests/seqgen.yaml" | kubectl apply -f -
    kubectl -n loadtest rollout status "deploy/$1" --timeout=120s
}

collect() { # -> $RUN_DIR/events.ndjson (dated channel files only: the top-level
            #    <channel>.json is a HARD LINK to the active dated file — reading
            #    both would double every event)
    mgr "find $CHANNEL_DIR -mindepth 2 -name '*.json' -exec cat {} + ; \
         find $CHANNEL_DIR -mindepth 2 -name '*.json.gz' -exec zcat {} +" > "$RUN_DIR/events.ndjson" 2>/dev/null
    wc -l "$RUN_DIR/events.ndjson"
}

verify() { # extra verifier args
    python3 "$QA_DIR/scripts/verify-sequences.py" "$RUN_DIR/events.ndjson" "$@" \
        | tee "$RUN_DIR/verify.txt"
    return "${PIPESTATUS[0]}"
}

snapshot_state() { # label — capture agent-side checkpoint for evidence
    kubectl -n wazuh exec "$(agent_pod)" -- cat /var/ossec/queue/k8s-logs/state.json \
        > "$RUN_DIR/state-$1.json" 2>/dev/null || true
}

wait_agent_ready() {
    kubectl -n wazuh rollout status ds/wazuh-agent --timeout=180s
    for _ in $(seq 1 30); do
        if agent_exec /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-logcollector is running"; then
            return 0
        fi
        sleep 2
    done
    echo "!! logcollector did not come up"; return 1
}

now() { python3 -c 'import time; print(f"{time.time():.3f}")'; }  # BSD date lacks %N

echo "=== scenario $SCENARIO -> $RUN_DIR"
RC=1

case "$SCENARIO" in
  S0) # sanity: steady stream, no restart -> 0 gaps / 0 dups + enrichment
    deploy_gen seqgen 3 5 0
    sleep 10; T0=$(now)
    sleep 300
    T1=$(now); sleep $SETTLE
    snapshot_state end; collect
    verify --since "$T0" --until "$T1" --expect-pods 3 --require-enrichment
    RC=$?
    ;;

  S1) # graceful in-pod restart (the acceptance scenario)
    deploy_gen seqgen 3 5 0
    sleep 10; T0=$(now)
    sleep 60
    snapshot_state pre
    echo "--- wazuh-control restart @ $(now)"
    agent_exec /var/ossec/bin/wazuh-control restart
    sleep 120
    T1=$(now); sleep $SETTLE
    snapshot_state end; collect
    verify --since "$T0" --until "$T1" --expect-pods 3
    RC=$?
    ;;

  S1b) # pod delete -> DaemonSet recreate (graceful via entrypoint TERM trap)
    deploy_gen seqgen 3 5 0
    sleep 10; T0=$(now)
    sleep 60
    snapshot_state pre
    echo "--- kubectl delete pod @ $(now)"
    kubectl -n wazuh delete pod "$(agent_pod)" --wait=true
    wait_agent_ready
    sleep 120
    T1=$(now); sleep $SETTLE
    snapshot_state end; collect
    verify --since "$T0" --until "$T1" --expect-pods 3
    RC=$?
    ;;

  S2) # crash (kill -9): at-least-once — dups allowed up to flush window
    RATE=5; PODS=3; FLUSH=12
    deploy_gen seqgen $PODS $RATE 0
    sleep 10; T0=$(now)
    sleep 60
    echo "--- kill -9 agent daemons @ $(now)"
    agent_exec bash -c 'kill -9 $(pidof wazuh-logcollector wazuh-agentd wazuh-modulesd wazuh-execd) 2>/dev/null; true'
    sleep 5
    agent_exec /var/ossec/bin/wazuh-control start
    sleep 120
    T1=$(now); sleep $SETTLE
    snapshot_state end; collect
    verify --since "$T0" --until "$T1" --expect-pods $PODS --max-dups $((RATE * PODS * FLUSH))
    RC=$?
    ;;

  S3) # rotation during downtime (1Mi rotation, ~1KB lines @ 50lps)
    deploy_gen floodgen 2 50 1000
    sleep 10; T0=$(now)
    sleep 30
    snapshot_state pre
    echo "--- stopping agent @ $(now)"
    agent_exec /var/ossec/bin/wazuh-control stop
    WORKER=$(kind get nodes --name wazuh-spike | grep worker | head -1)
    BEFORE=$(docker exec "$WORKER" bash -c 'ls /var/log/pods/loadtest_floodgen*/gen/ 2>/dev/null | wc -l')
    echo "--- waiting for >=2 rotations (files now: $BEFORE)"
    for _ in $(seq 1 60); do
        NOW_FILES=$(docker exec "$WORKER" bash -c 'ls /var/log/pods/loadtest_floodgen*/gen/ 2>/dev/null | wc -l')
        [ "$NOW_FILES" -ge $((BEFORE + 2)) ] && break
        sleep 5
    done
    docker exec "$WORKER" bash -c 'ls -la /var/log/pods/loadtest_floodgen*/gen/' || true
    echo "--- starting agent @ $(now)"
    agent_exec /var/ossec/bin/wazuh-control start
    sleep 150
    T1=$(now); sleep $SETTLE
    snapshot_state end; collect
    verify --since "$T0" --until "$T1" --expect-pods 2
    RC=$?
    kubectl -n loadtest delete deploy/floodgen --ignore-not-found
    ;;

  S4) # container created while the agent is down -> must start at SEQ 0
    deploy_gen seqgen 3 5 0
    sleep 10
    echo "--- stopping agent @ $(now)"
    agent_exec /var/ossec/bin/wazuh-control stop
    T0=$(now)
    deploy_gen seqgen-late 1 5 0
    sleep 30
    echo "--- starting agent @ $(now)"
    agent_exec /var/ossec/bin/wazuh-control start
    sleep 120
    T1=$(now); sleep $SETTLE
    snapshot_state end; collect
    echo "--- checking only the late pod (zero start)"
    python3 "$QA_DIR/scripts/verify-sequences.py" "$RUN_DIR/events.ndjson" \
        --since "$T0" --until "$T1" --require-zero-start --expect-pods 4 \
        | tee "$RUN_DIR/verify.txt"
    RC=${PIPESTATUS[0]}
    kubectl -n loadtest delete deploy/seqgen-late --ignore-not-found
    ;;

  *) echo "unknown scenario $SCENARIO"; exit 2 ;;
esac

echo "=== scenario $SCENARIO rc=$RC (evidence: $RUN_DIR)"
exit "$RC"
