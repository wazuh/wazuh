#!/usr/bin/env bash
#
# run_case_bench.sh — one-shot orchestrator for the case-preservation benchmark.
#
# Runs the scenario to completion (run_benchmark.sh generates summary.json +
# charts on its own), auto-times the enrichment probe so a later syscollector
# delta re-hits the enriched docs, then verifies. No second shell, no Ctrl-C.
#
# It also HEALTH-CHECKS the run: if 0 sessions completed (e.g. the manager
# rejected the Start handshake) it fails loudly, so a false "verify OK" against
# stale docs from an earlier run cannot happen.
#
# Usage:
#   ./run_case_bench.sh [label] [present|absent|skip]
#     label   results dir suffix          (default: after_feature)
#     expect  case.* survives? present=feature, absent=baseline, skip=no probe
#             (default: present)
#
# Env (same names as indexer_control.sh / enrich_docs.sh):
#   INDEXER_HOST(localhost) INDEXER_PORT(9200) INDEXER_USER(admin) INDEXER_PASS(admin)
#   SCENARIO(scenarios/case_preservation_bench_mixed40.json)  IDX(...-processes)
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

LABEL="${1:-after_feature}"
EXPECT="${2:-present}"
SCENARIO="${SCENARIO:-scenarios/case_preservation_bench_mixed40.json}"
IDX="${IDX:-wazuh-states-inventory-processes}"
INDEXER_HOST="${INDEXER_HOST:-localhost}"; INDEXER_PORT="${INDEXER_PORT:-9200}"
INDEXER_USER="${INDEXER_USER:-admin}";     INDEXER_PASS="${INDEXER_PASS:-admin}"
LIB="/workspaces/devContainer/wazuh/src/build/lib/libindexer_connector.so"
RESULTS_DIR="results_${LABEL}"
BASE="https://${INDEXER_HOST}:${INDEXER_PORT}"
CURL=(curl -sk -u "${INDEXER_USER}:${INDEXER_PASS}")

hr() { printf '%s\n' "======================================================================"; }
hr; echo " Case-preservation benchmark   label=${LABEL}   expect=${EXPECT}"
echo " scenario=${SCENARIO}"; hr

# --- 0. Which build is live -------------------------------------------------
if command -v nm >/dev/null 2>&1 && [[ -f "$LIB" ]]; then
  n=$(nm -DC "$LIB" 2>/dev/null | grep -c bulkUpsertPreserving || true)
  echo "[build] libindexer_connector.so bulkUpsertPreserving symbols: ${n}  ($([[ ${n} -gt 0 ]] && echo FEATURE || echo BASELINE))"
  if [[ "$EXPECT" == "present" && "${n}" -eq 0 ]]; then echo "[build] WARNING: expect=present but BASELINE libs are live"; fi
  if [[ "$EXPECT" == "absent"  && "${n}" -gt 0 ]]; then echo "[build] WARNING: expect=absent but FEATURE libs are live"; fi
fi

# --- 1. Preflight -----------------------------------------------------------
if ! "${CURL[@]}" "${BASE}/_cluster/health" >/dev/null 2>&1; then
  echo "[error] indexer not reachable at ${BASE} — start it (./indexer_control.sh start)"; exit 1
fi
echo "[ok] indexer reachable at ${BASE}"
if ! /var/wazuh-manager/bin/wazuh-manager-control status 2>/dev/null | grep -q "modulesd is running"; then
  echo "[error] wazuh-manager-modulesd is not running — start the manager first"; exit 1
fi
echo "[ok] manager modulesd running"

# --- 2. Start the benchmark in the background -------------------------------
# run_benchmark.sh starts the monitor, runs the sender, then writes summary.json
# and charts/ by itself. DO NOT Ctrl-C it. Expect ~6-10 min (grace + key-wait +
# load + drain + post-run grace).
echo "[run] starting run_benchmark.sh — runs to completion by itself (~6-10 min)."
echo "[run] live log: tail -f ${SCRIPT_DIR}/run_${LABEL}.log"
mkdir -p "$RESULTS_DIR"
./run_benchmark.sh --scenario "$SCENARIO" --label "$LABEL" > "run_${LABEL}.log" 2>&1 &
BENCH_PID=$!

# --- 3. Enrichment probe (auto-timed) ---------------------------------------
# enrich_docs.sh polls for docs itself (handles registration + key-wait delay),
# then adds the case mapping and enriches ~20 docs. Runs concurrently while the
# benchmark keeps sending, so a later syscollector delta re-hits the enriched _ids.
if [[ "$EXPECT" != "skip" ]]; then
  echo "[enrich] launching preservation probe (auto-waits for full-sync docs)..."
  IDX="$IDX" INDEXER_HOST="$INDEXER_HOST" INDEXER_PORT="$INDEXER_PORT" \
  INDEXER_USER="$INDEXER_USER" INDEXER_PASS="$INDEXER_PASS" DEADLINE_S=240 \
    ./enrich_docs.sh "${RESULTS_DIR}/enriched_ids.txt" || echo "[enrich] WARNING: enrichment failed (probe will be inconclusive)"
else
  echo "[enrich] skipped (expect=skip)"
fi

# --- 4. Wait for the benchmark to finish ------------------------------------
echo "[run] waiting for run_benchmark to finish (summary + charts are written at the end)..."
wait "$BENCH_PID"; RC=$?
echo "[run] run_benchmark exited (rc=${RC})."

# --- 5. Health check: did the run actually sync? ----------------------------
BENCH_CSV="${RESULTS_DIR}/bench.csv"
if [[ -f "$BENCH_CSV" ]]; then
  read -r COMPLETED FAILED STARTED < <(python3 - "$BENCH_CSV" <<'PY'
import csv,sys
rows=list(csv.DictReader(open(sys.argv[1])))
def mx(c):
    try: return max(int(float(r.get(c,0) or 0)) for r in rows)
    except: return 0
print(mx("sessions_completed"), mx("sessions_failed"), mx("sessions_started"))
PY
)
  echo "[health] sessions started=${STARTED} completed=${COMPLETED} failed=${FAILED}"
  if [[ "${COMPLETED:-0}" -eq 0 ]]; then
    echo "[health] *** FAIL: 0 sessions completed — the run synced NOTHING. Results are invalid."
    echo "[health] Check: grep 'Cluster name validation' /var/wazuh-manager/logs/wazuh-manager.log"
    echo "[health] (Any 'verify present' below would be against STALE docs — do not trust it.)"
  else
    echo "[health] OK — sessions completed > 0, the run exercised the real path."
  fi
else
  echo "[health] WARNING: no ${BENCH_CSV} — run may have been interrupted."
fi

# --- 6. Verify preservation --------------------------------------------------
if [[ "$EXPECT" != "skip" ]]; then
  echo "[verify] checking case.* on enriched docs (expect all ${EXPECT})..."
  IDX="$IDX" INDEXER_HOST="$INDEXER_HOST" INDEXER_PORT="$INDEXER_PORT" \
  INDEXER_USER="$INDEXER_USER" INDEXER_PASS="$INDEXER_PASS" \
    ./verify_case.sh "${RESULTS_DIR}/enriched_ids.txt" "$EXPECT" || true
fi

# --- 7. Point at artifacts ---------------------------------------------------
hr
echo " Done. Artifacts in ${RESULTS_DIR}/:"
echo "   summary.json                    descriptive aggregate"
echo "   charts/                         $(ls "${RESULTS_DIR}/charts" 2>/dev/null | wc -l) PNGs (incl. monitor_cpu_total_with_indexer.png)"
echo "   monitor/wazuh-indexer.csv       indexer CPU/RSS (captured automatically)"
echo "   run_${LABEL}.log                full orchestrator/run log"
hr
