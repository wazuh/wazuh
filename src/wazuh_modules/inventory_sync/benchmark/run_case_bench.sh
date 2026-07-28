#!/usr/bin/env bash
#
# run_case_bench.sh — one-shot orchestrator for the case-preservation benchmark.
#
# Runs the scenario to completion (run_benchmark.sh generates summary.json +
# charts on its own), auto-times the enrichment probe so a later syscollector
# delta re-hits the enriched docs, then verifies. No second shell, no Ctrl-C.
#
# It HEALTH-CHECKS each run: if 0 sessions completed (e.g. the manager
# rejected the Start handshake) it fails loudly, so a false "verify OK" against
# stale docs from an earlier run cannot happen.
#
# It repeats the whole run REPEATS times (default 3, per the benchmark plan:
# report the median, use min/max as spread). Before each run it resets state
# (deletes wazuh-states-inventory-* and bench-* agents) so every repetition
# starts from the same empty baseline.
#
# Usage:
#   ./run_case_bench.sh [label] [present|absent|skip] [repeats]
#     label    results dir suffix          (default: after_feature)
#     expect   case.* survives? present=feature, absent=baseline, skip=no probe
#              (default: present)
#     repeats  runs of the same scenario   (default: 3; 1 = one full repetition)
#              This does not reduce the workload defined by the scenario.
#              N>1 → results_<label>_r1..rN; N=1 → results_<label>
#
# Env (same names as indexer_control.sh / enrich_docs.sh):
#   INDEXER_HOST(localhost) INDEXER_PORT(9200) INDEXER_USER(admin) INDEXER_PASS(admin)
#   SCENARIO(scenarios/case_preservation_smoke.json)  IDX(...-processes)
#   CLEAN(1)    reset indices+agents before each run; CLEAN=0 keeps them
#   PAUSE_S(30) settle time between repeats
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

LABEL="${1:-after_feature}"
EXPECT="${2:-present}"
REPEATS="${3:-${REPEATS:-3}}"
SCENARIO="${SCENARIO:-scenarios/case_preservation_smoke.json}"
IDX="${IDX:-wazuh-states-inventory-processes}"
INDEXER_HOST="${INDEXER_HOST:-localhost}"; INDEXER_PORT="${INDEXER_PORT:-9200}"
INDEXER_USER="${INDEXER_USER:-admin}";     INDEXER_PASS="${INDEXER_PASS:-admin}"
CLEAN="${CLEAN:-1}"
PAUSE_S="${PAUSE_S:-30}"
MAX_DISK_PERCENT="${MAX_DISK_PERCENT:-95}"
INTERNAL_OPTIONS="${INTERNAL_OPTIONS:-/var/wazuh-manager/etc/wazuh-manager-internal-options.conf}"
BASE="https://${INDEXER_HOST}:${INDEXER_PORT}"
CURL=(curl -sSk --fail-with-body -u "${INDEXER_USER}:${INDEXER_PASS}")

if [[ "$(basename "$SCENARIO")" == "state_case_management_update_comparison.json" &&
      "$EXPECT" != "skip" ]]; then
  echo "[error] ${SCENARIO} is performance-only; use expect=skip so enrichment does not contaminate metrics."
  exit 1
fi

hr() { printf '%s\n' "======================================================================"; }
hr; echo " Case-preservation benchmark   label=${LABEL}   expect=${EXPECT}   repeats=${REPEATS}"
echo " scenario=${SCENARIO}   (load and duration are defined by the scenario)"; hr

# --- 1. Preflight -----------------------------------------------------------
if ! health=$("${CURL[@]}" "${BASE}/_cluster/health"); then
  echo "[error] indexer not reachable at ${BASE} — start it (./indexer_control.sh start)"; exit 1
fi
health_status=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("status", "unknown"))' <<<"$health")
if [[ "$health_status" == "red" || "$health_status" == "unknown" ]]; then
  echo "[error] indexer cluster health is ${health_status}"; exit 1
fi
allocation=$("${CURL[@]}" "${BASE}/_cat/allocation?format=json&h=disk.percent")
disk_percent=$(python3 -c 'import json,sys; print(max([int(x["disk.percent"]) for x in json.load(sys.stdin) if x.get("disk.percent") not in (None,"")], default=0))' <<<"$allocation")
if (( disk_percent >= MAX_DISK_PERCENT )); then
  echo "[error] indexer disk usage ${disk_percent}% reached benchmark limit ${MAX_DISK_PERCENT}%"; exit 1
fi
blocks=$("${CURL[@]}" "${BASE}/wazuh-states-*/_settings?ignore_unavailable=true&filter_path=*.settings.index.blocks.read_only_allow_delete")
blocked_indices=$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(v.get("settings",{}).get("index",{}).get("blocks",{}).get("read_only_allow_delete") in (True,"true") for v in d.values()))' <<<"$blocks")
if (( blocked_indices > 0 )); then
  echo "[error] ${blocked_indices} state indices are read_only_allow_delete"; exit 1
fi
echo "[ok] indexer writable: health=${health_status} disk=${disk_percent}%"

manager_status=$(/var/wazuh-manager/bin/wazuh-manager-control status 2>/dev/null || true)
if [[ "$manager_status" != *"modulesd is running"* ]]; then
  echo "[error] wazuh-manager-modulesd is not running — start the manager first"; exit 1
fi
echo "[ok] manager modulesd running"

debug_level=0
if [[ -f "$INTERNAL_OPTIONS" ]]; then
  debug_level=$(awk -F= '$1 == "wazuh_modules.debug" {value=$2} END {print value == "" ? 0 : value}' "$INTERNAL_OPTIONS")
fi
if [[ "$debug_level" != "0" ]]; then
  echo "[error] wazuh_modules.debug=${debug_level}; performance runs require debug=0"; exit 1
fi
echo "[ok] manager debug level is 0"

modulesd_pid=$(pgrep -f '^/var/wazuh-manager/bin/wazuh-manager-modulesd([[:space:]]|$)' | head -1 || true)
if [[ -z "$modulesd_pid" ]]; then
  echo "[error] cannot resolve the running modulesd PID"; exit 1
fi
LIB=$(awk '$NF ~ /libindexer_connector\.so$/ {print $NF; exit}' "/proc/${modulesd_pid}/maps")
if [[ -z "$LIB" || ! -f "$LIB" ]]; then
  echo "[error] cannot resolve the libindexer_connector.so loaded by modulesd PID ${modulesd_pid}"; exit 1
fi
n=$(nm -DC "$LIB" 2>/dev/null | grep -c bulkIndexWithConcurrencyControl || true)
echo "[build] loaded=${LIB} bulkIndexWithConcurrencyControl_symbols=${n}"
export BENCH_GIT_COMMIT
BENCH_GIT_COMMIT=$(git -C "$SCRIPT_DIR" rev-parse HEAD)
export BENCH_LIBRARY_PATH="$LIB"
export BENCH_LIBRARY_SHA256
BENCH_LIBRARY_SHA256=$(sha256sum "$LIB" | awk '{print $1}')

read -r EXPECTED_AGENTS EXPECTED_SESSIONS < <(python3 - "$SCENARIO" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
lanes = d["lanes"]
if "fleets" in d:
    agents = sum(int(f["agents"]) for f in d["fleets"])
    sessions = sum(
        int(f["agents"]) * sum(
            sum(int(step.get("repeat_count", 1)) for step in lanes[lane])
            for lane in f["lanes"]
        )
        for f in d["fleets"]
    )
else:
    agents = int(d.get("total_agents", 1))
    sessions = agents * sum(
        sum(int(step.get("repeat_count", 1)) for step in steps)
        for steps in lanes.values()
    )
print(agents, sessions)
PY
)
echo "[ok] expected workload: agents=${EXPECTED_AGENTS} sessions=${EXPECTED_SESSIONS}"

# --- Reset state so every repetition starts from the same baseline -----------
clean_state() {
  [[ "$CLEAN" == "1" ]] || { echo "[clean] skipped (CLEAN=0)"; return 0; }
  echo "[clean] deleting benchmark state indices + bench-* agents"
  if ! "${CURL[@]}" -X DELETE \
      "${BASE}/wazuh-states-inventory-*,wazuh-states-fim-*,wazuh-states-sca*,wazuh-states-vulnerabilities*?ignore_unavailable=true" \
      >/dev/null; then
    echo "[clean] ERROR: state index cleanup failed"; return 1
  fi
  if ! ./cleanup_agents.sh >/dev/null; then
    echo "[clean] ERROR: cleanup_agents.sh failed"; return 1
  fi
  echo "[clean] complete"
}

# --- One full run: benchmark + enrichment + health check + verify ------------
run_once() {
  local run_label="$1"
  local results_dir="results_${run_label}"
  local rc_health=0

  # run_benchmark.sh starts the monitor, runs the sender, then writes
  # summary.json and charts/ by itself. Expect ~6-10 min.
  echo "[run] starting run_benchmark.sh — live log: tail -f ${SCRIPT_DIR}/run_${run_label}.log"
  mkdir -p "$results_dir"
  INDEXER_HOST="$INDEXER_HOST" INDEXER_PORT="$INDEXER_PORT" \
    INDEXER_USER="$INDEXER_USER" INDEXER_PASS="$INDEXER_PASS" \
      ./run_benchmark.sh --scenario "$SCENARIO" --label "$run_label" \
        > "run_${run_label}.log" 2>&1 &
  local bench_pid=$!

  # enrich_docs.sh polls for docs itself (handles registration + key-wait
  # delay), then adds the case mapping and enriches ~20 docs. Runs while the
  # benchmark keeps sending, so a later syscollector delta re-hits those _ids.
  if [[ "$EXPECT" != "skip" ]]; then
    echo "[enrich] launching preservation probe (auto-waits for full-sync docs)..."
    if ! IDX="$IDX" INDEXER_HOST="$INDEXER_HOST" INDEXER_PORT="$INDEXER_PORT" \
      INDEXER_USER="$INDEXER_USER" INDEXER_PASS="$INDEXER_PASS" DEADLINE_S=240 \
        ./enrich_docs.sh "${results_dir}/enriched_docs.jsonl"; then
      echo "[enrich] ERROR: enrichment failed"
      rc_health=1
    fi
  else
    echo "[enrich] skipped (expect=skip)"
  fi

  echo "[run] waiting for run_benchmark to finish (summary + charts are written at the end)..."
  local bench_rc=0
  wait "$bench_pid" || bench_rc=$?
  echo "[run] run_benchmark exited (rc=${bench_rc})."
  if [[ "$bench_rc" -ne 0 ]]; then
    rc_health=1
  fi

  # Health check: did the run actually sync?
  local sender_summary="${results_dir}/sender_summary.json"
  if [[ -f "$sender_summary" ]]; then
    read -r REGISTERED STARTED COMPLETED FAILED DROPPED < <(python3 - "$sender_summary" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
m = d.get("messages", {})
meta = d.get("meta", {})
print(meta.get("agents_registered", 0),
      m.get("sessions_started", 0),
      m.get("sessions_completed", 0),
      m.get("sessions_failed", 0),
      m.get("messages_dropped", 0))
PY
)
    echo "[health] agents=${REGISTERED}/${EXPECTED_AGENTS} sessions=${STARTED}/${COMPLETED}/${FAILED} expected=${EXPECTED_SESSIONS} dropped=${DROPPED}"
    if [[ "$REGISTERED" -ne "$EXPECTED_AGENTS" ||
          "$STARTED" -ne "$EXPECTED_SESSIONS" ||
          "$COMPLETED" -ne "$EXPECTED_SESSIONS" ||
          "$FAILED" -ne 0 ||
          "$DROPPED" -ne 0 ]]; then
      echo "[health] *** FAIL: cumulative workload totals do not match the scenario."
      rc_health=1
    else
      echo "[health] OK — cumulative workload totals are complete."
    fi
  else
    echo "[health] ERROR: no ${sender_summary}"
    rc_health=1
  fi

  for required_file in \
    "${results_dir}/monitor/wazuh-manager-modulesd.csv" \
    "${results_dir}/monitor/wazuh-indexer.csv" \
    "${results_dir}/indexer_stats_before.json" \
    "${results_dir}/indexer_stats_after.json"; do
    if [[ ! -s "$required_file" ]]; then
      echo "[health] ERROR: missing monitor artifact ${required_file}"
      rc_health=1
    fi
  done

  if [[ "$EXPECT" != "skip" ]]; then
    echo "[verify] checking case.* on enriched docs (expect all ${EXPECT})..."
    if ! IDX="$IDX" INDEXER_HOST="$INDEXER_HOST" INDEXER_PORT="$INDEXER_PORT" \
      INDEXER_USER="$INDEXER_USER" INDEXER_PASS="$INDEXER_PASS" \
        ./verify_case.sh "${results_dir}/enriched_docs.jsonl" "$EXPECT"; then
      rc_health=1
    fi
  fi

  return "$rc_health"
}

# --- Repeat loop --------------------------------------------------------------
OVERALL=0
RUN_DIRS=()
for i in $(seq 1 "$REPEATS"); do
  if [[ "$REPEATS" -gt 1 ]]; then run_label="${LABEL}_r${i}"; else run_label="$LABEL"; fi
  hr; echo " Run ${i}/${REPEATS}   → results_${run_label}"; hr
  if ! clean_state; then
    OVERALL=1
    break
  fi
  run_once "$run_label" || OVERALL=1
  RUN_DIRS+=("results_${run_label}")
  if [[ "$i" -lt "$REPEATS" ]]; then
    echo "[pause] ${PAUSE_S}s settle before next run..."
    sleep "$PAUSE_S"
  fi
done

# --- Point at artifacts --------------------------------------------------------
hr
echo " Done (${REPEATS} run(s), health=$([[ $OVERALL -eq 0 ]] && echo OK || echo FAILED)). Per run dir:"
echo "   summary.json                    descriptive aggregate"
echo "   charts/                         PNGs (incl. monitor_cpu_total_with_indexer.png)"
echo "   monitor/wazuh-indexer.csv       indexer CPU/RSS (captured automatically)"
echo "   indexer_stats_before.json       raw OpenSearch counters before sender"
echo "   indexer_stats_after.json        raw OpenSearch counters after sender"
echo "   run_<label>.log                 full orchestrator/run log"
if [[ "${#RUN_DIRS[@]}" -gt 1 ]]; then
  echo
  echo " Compare repeats (report the median, min/max as spread):"
  echo "   ./run_benchmark.sh --compare ${RUN_DIRS[*]}"
fi
echo
echo " Feature-vs-baseline comparison (after both labels are run):"
echo "   ./run_benchmark.sh --compare results_${LABEL}_r1 results_<other_label>_r1 ..."
hr
exit "$OVERALL"
