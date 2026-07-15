#!/bin/bash
# Per-cell perf sampler for the #36101 spike matrix.
# Usage: sample-perf.sh <pods> <rate> <duration-s> <evidence-dir>
#
# Drives one matrix cell: scales the seqgen deployment, waits for steady
# state, samples agent-process CPU/RSS/fds every 5s for <duration>, then
# verifies the window (gaps/dups/lag) and emits a one-line CSV summary.
set -uo pipefail

PODS=${1:?pods}
RATE=${2:?rate}
DURATION=${3:?duration seconds}
EVIDENCE=${4:-"$HOME/Dev/jr0me/wazuh-36101-spike/evidence/perf"}
REPO_ROOT=$(git rev-parse --show-toplevel)
QA_DIR="$REPO_ROOT/src/wazuh_modules/container_connector/qa/kind"
CHANNEL_DIR=/var/wazuh-manager/logs/standard-wazuh-events-v5

CELL="p${PODS}-r${RATE}"
RUN_DIR="$EVIDENCE/$CELL"
mkdir -p "$RUN_DIR"

mgr() { docker exec wazuh-server bash -c "$*"; }
now() { python3 -c 'import time; print(f"{time.time():.3f}")'; }

agent_pod() {
    kubectl -n wazuh get pod -l app=wazuh-agent \
        -o jsonpath='{.items[?(@.status.phase=="Running")].metadata.name}' | awk '{print $1}'
}

echo "=== cell $CELL: $PODS pods x $RATE lines/s for ${DURATION}s"
SEQGEN_NAME=seqgen SEQGEN_REPLICAS=$PODS SEQGEN_RATE=$RATE SEQGEN_PAD=0 \
    envsubst < "$QA_DIR/manifests/seqgen.yaml" | kubectl apply -f - >/dev/null
kubectl -n loadtest rollout status deploy/seqgen --timeout=300s >/dev/null || exit 1

echo "--- settling 30s (tracking + steady state)"
sleep 30
POD=$(agent_pod)

# /proc sampler runs INSIDE the agent pod; CPU = utime+stime delta per process.
SAMPLER='
CLK=$(getconf CLK_TCK)
echo "epoch,proc,cpu_pct,rss_kb,fds"
declare -A prev
while true; do
  for name in wazuh-logcollector wazuh-modulesd wazuh-agentd; do
    pid=$(pidof "$name" | awk "{print \$1}")
    [ -z "$pid" ] && continue
    ticks=$(awk "{print \$14+\$15}" /proc/$pid/stat 2>/dev/null) || continue
    rss=$(awk "/VmRSS/{print \$2}" /proc/$pid/status 2>/dev/null)
    fds=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
    t=$(date +%s)
    key="$name"
    if [ -n "${prev[$key]:-}" ]; then
      read pt pticks <<< "${prev[$key]}"
      dt=$((t - pt)); dticks=$((ticks - pticks))
      if [ "$dt" -gt 0 ]; then
        cpu=$(awk "BEGIN{printf \"%.1f\", 100*$dticks/$CLK/$dt}")
        echo "$t,$name,$cpu,$rss,$fds"
      fi
    fi
    prev[$key]="$t $ticks"
  done
  sleep 5
done'

T0=$(now)
kubectl -n wazuh exec "$POD" -- bash -c "$SAMPLER" > "$RUN_DIR/samples.csv" &
SAMPLER_PID=$!
( while true; do docker stats --no-stream --format '{{.Name}},{{.CPUPerc}},{{.MemUsage}}' wazuh-spike-worker wazuh-server 2>/dev/null; sleep 10; done ) > "$RUN_DIR/node-stats.csv" &
NODE_PID=$!

sleep "$DURATION"
T1=$(now)
kill $SAMPLER_PID $NODE_PID 2>/dev/null
wait $SAMPLER_PID $NODE_PID 2>/dev/null

echo "--- settling 25s, then collect + verify"
sleep 25
mgr "find $CHANNEL_DIR -mindepth 2 -name '*.json' -exec cat {} + ; \
     find $CHANNEL_DIR -mindepth 2 -name '*.json.gz' -exec zcat {} +" > "$RUN_DIR/events.ndjson" 2>/dev/null

python3 "$QA_DIR/scripts/verify-sequences.py" "$RUN_DIR/events.ndjson" \
    --since "$T0" --until "$T1" --expect-pods "$PODS" > "$RUN_DIR/verify.txt" 2>&1
VRC=$?

# manager saturation check: analysisd-equivalent in 5.0 is the engine; we
# record the indexer-connector/agent queue state via wazuh-control + archives size
mgr "ls -la $CHANNEL_DIR/*.json | tail -1" > "$RUN_DIR/channel-size.txt" 2>/dev/null

# cell summary: max RSS + mean CPU per proc + lag from verify.txt
python3 - "$RUN_DIR" "$CELL" "$PODS" "$RATE" "$VRC" <<'PY'
import csv, re, sys, os
run_dir, cell, pods, rate, vrc = sys.argv[1:6]
stats = {}
with open(os.path.join(run_dir, "samples.csv")) as f:
    for row in csv.DictReader(f):
        s = stats.setdefault(row["proc"], {"cpu": [], "rss": 0, "fds": 0})
        try:
            s["cpu"].append(float(row["cpu_pct"]))
            s["rss"] = max(s["rss"], int(row["rss_kb"]))
            s["fds"] = max(s["fds"], int(row["fds"]))
        except ValueError:
            pass
lag = ""
with open(os.path.join(run_dir, "verify.txt")) as f:
    for line in f:
        m = re.match(r"lag: (.*)", line)
        if m:
            lag = m.group(1)
out = [cell, pods, rate, "PASS" if vrc == "0" else f"FAIL({vrc})", lag]
for proc in ("wazuh-logcollector", "wazuh-modulesd", "wazuh-agentd"):
    s = stats.get(proc, {"cpu": [0], "rss": 0, "fds": 0})
    cpu = sum(s["cpu"]) / max(1, len(s["cpu"]))
    out.append(f"{proc.split('-')[1]}: cpu={cpu:.1f}% rss={s['rss']/1024:.1f}MB fds={s['fds']}")
print(" | ".join(str(x) for x in out))
PY
