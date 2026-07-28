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
#     repeats  runs of the same scenario   (default: 3; 1 = single smoke run)
#              N>1 → results_<label>_r1..rN; N=1 → results_<label>
#
# Env (same names as indexer_control.sh / enrich_docs.sh):
#   INDEXER_HOST(localhost) INDEXER_PORT(9200) INDEXER_USER(admin) INDEXER_PASS(admin)
#   SCENARIO(scenarios/case_preservation_bench_mixed40.json)  IDX(...-processes)
#   CLEAN(1)    reset indices+agents before each run; CLEAN=0 keeps them
#   PAUSE_S(30) settle time between repeats
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

LABEL="${1:-after_feature}"
EXPECT="${2:-present}"
REPEATS="${3:-${REPEATS:-3}}"
SCENARIO="${SCENARIO:-scenarios/case_preservation_bench_mixed40.json}"
IDX="${IDX:-wazuh-states-inventory-processes}"
INDEXER_HOST="${INDEXER_HOST:-localhost}"; INDEXER_PORT="${INDEXER_PORT:-9200}"
INDEXER_USER="${INDEXER_USER:-admin}";     INDEXER_PASS="${INDEXER_PASS:-admin}"
CLEAN="${CLEAN:-1}"
PAUSE_S="${PAUSE_S:-30}"
LIB="/workspaces/devContainer/wazuh/src/build/lib/libindexer_connector.so"
BASE="https://${INDEXER_HOST}:${INDEXER_PORT}"
CURL=(curl -sk -u "${INDEXER_USER}:${INDEXER_PASS}")

hr() { printf '%s\n' "======================================================================"; }
hr; echo " Case-preservation benchmark   label=${LABEL}   expect=${EXPECT}   repeats=${REPEATS}"
echo " scenario=${SCENARIO}"
echo " Run time scales with the scenario's parallel_agents (10 -> ~35-45 min/run)."
echo " Ctrl-C does NOT stop run_benchmark/benchmark_sender; to abort use:"
echo "   pkill -f run_case_bench; pkill -f run_benchmark.sh; pkill -f benchmark_sender"; hr

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
if ! /var/wazuh-manager/bin/wazuh-manager-control status 2>/dev/null | grep "wazuh-manager-modulesd is running"; then
  echo "[error] wazuh-manager-modulesd is not running — start the manager first"; exit 1
fi
echo "[ok] manager modulesd running"

# Zombie-session guard: a wedged previous run leaves sessions holding the
# inventory-sync DataValue quota until the session-timeout reaper fires
# (~28 min). Any run started in that window gets its Starts rejected and
# syncs nothing. Requires the dbsync_metrics patch stats line; skipped if absent.
if stats_line=$(grep "InventorySync queue stats" /var/wazuh-manager/logs/wazuh-manager.log 2>/dev/null | tail -1) && [[ -n "$stats_line" ]]; then
  sessions_now=$(grep -oE 'sessions=[0-9]+' <<<"$stats_line" | head -1 | cut -d= -f2)
  quota_pct=$(grep -oE 'data_value_quota_used_pct=[0-9.]+' <<<"$stats_line" | cut -d= -f2)
  if [[ "${sessions_now:-0}" -gt 0 || "${quota_pct%%.*}" -gt 0 ]]; then
    echo "[error] manager holds ${sessions_now:-?} leftover inventory-sync session(s) using ${quota_pct:-?}% of the DataValue quota"
    echo "[error] (zombie state from a previous run) — restart the manager first, or override with SKIP_SESSION_CHECK=1"
    [[ "${SKIP_SESSION_CHECK:-0}" == "1" ]] || exit 1
  fi
  echo "[ok] no leftover sessions (quota used: ${quota_pct:-0}%)"
fi

# --- Reset state so every repetition starts from the same baseline -----------
clean_state() {
  [[ "$CLEAN" == "1" ]] || { echo "[clean] skipped (CLEAN=0)"; return 0; }
  echo "[clean] deleting wazuh-states-inventory-* indices + bench-* agents"
  "${CURL[@]}" -X DELETE "${BASE}/wazuh-states-inventory-*" >/dev/null 2>&1 || true
  ./cleanup_agents.sh >/dev/null 2>&1 || echo "[clean] WARNING: cleanup_agents.sh failed (API down?) — continuing"
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
  ./run_benchmark.sh --scenario "$SCENARIO" --label "$run_label" > "run_${run_label}.log" 2>&1 &
  local bench_pid=$!
  local bench_t0=$SECONDS

  # enrich_docs.sh polls for docs itself (handles registration + key-wait
  # delay), then adds the case mapping and enriches ~20 docs. Runs while the
  # benchmark keeps sending, so a later syscollector delta re-hits those _ids.
  if [[ "$EXPECT" != "skip" ]]; then
    echo "[enrich] launching preservation probe (auto-waits for full-sync docs)..."
    IDX="$IDX" INDEXER_HOST="$INDEXER_HOST" INDEXER_PORT="$INDEXER_PORT" \
    INDEXER_USER="$INDEXER_USER" INDEXER_PASS="$INDEXER_PASS" DEADLINE_S=240 \
      ./enrich_docs.sh "${results_dir}/enriched_ids.txt" || echo "[enrich] WARNING: enrichment failed (probe will be inconclusive)"
  else
    echo "[enrich] skipped (expect=skip)"
  fi

  # Progress watcher: one status line every PROGRESS_S seconds (default 30)
  # so the long silent phases (per-wave registration + 35s key-wait, indexer
  # flush waits, final drain) don't look like a hang. Quiet stretches under
  # ~2 min are normal between agent waves.
  (
    local_last=""; local_stall=0
    while kill -0 "$bench_pid" 2>/dev/null; do
      sleep "${PROGRESS_S:-30}"
      kill -0 "$bench_pid" 2>/dev/null || break
      el=$((SECONDS - bench_t0))
      if [[ -f "${results_dir}/bench.csv" ]]; then
        read -r P_ST P_CO P_FA < <(python3 - "${results_dir}/bench.csv" <<'PY'
import csv, sys
rows = list(csv.DictReader(open(sys.argv[1])))
t = lambda c: sum(int(float(r.get(c) or 0)) for r in rows)
print(t("sessions_started"), t("sessions_completed"), t("sessions_failed"))
PY
) || continue
        note=""
        if [[ "${P_ST}/${P_CO}" == "$local_last" ]]; then
          local_stall=$((local_stall + 1))
          if [[ $local_stall -ge 4 ]]; then
            note="  <- no change for $((local_stall * ${PROGRESS_S:-30}))s (key-wait between waves is normal; >5 min: check 'queue stats' in the manager log)"
          fi
        else
          local_stall=0
        fi
        local_last="${P_ST}/${P_CO}"
        printf '[progress %02d:%02d] sessions started=%s completed=%s failed=%s in-flight=%s%s\n' \
          $((el / 60)) $((el % 60)) "$P_ST" "$P_CO" "$P_FA" $((P_ST - P_CO)) "$note"
      else
        printf '[progress %02d:%02d] warming up (agent registration + key-wait)...\n' $((el / 60)) $((el % 60))
      fi
    done
  ) &
  local watch_pid=$!

  echo "[run] waiting for run_benchmark to finish (summary + charts are written at the end)..."
  wait "$bench_pid"
  echo "[run] run_benchmark exited (rc=$?)."
  kill "$watch_pid" 2>/dev/null
  wait "$watch_pid" 2>/dev/null

  # Health check: did the run actually sync? Totals come from
  # sender_summary.json (bench.csv columns are per-second deltas, so they
  # are summed as a fallback, never max'ed).
  local bench_csv="${results_dir}/bench.csv"
  if [[ -f "${results_dir}/sender_summary.json" || -f "$bench_csv" ]]; then
    read -r COMPLETED FAILED STARTED < <(python3 - "$results_dir" <<'PY'
import csv, json, os, sys
d = sys.argv[1]
sj = os.path.join(d, "sender_summary.json")
if os.path.exists(sj):
    m = json.load(open(sj))["messages"]
    print(m.get("sessions_completed", 0), m.get("sessions_failed", 0), m.get("sessions_started", 0))
else:
    rows = list(csv.DictReader(open(os.path.join(d, "bench.csv"))))
    def tot(c):
        try: return sum(int(float(r.get(c) or 0)) for r in rows)
        except Exception: return 0
    print(tot("sessions_completed"), tot("sessions_failed"), tot("sessions_started"))
PY
)
    echo "[health] sessions started=${STARTED} completed=${COMPLETED} failed=${FAILED}"
    if [[ "${COMPLETED:-0}" -eq 0 ]]; then
      echo "[health] *** FAIL: 0 sessions completed — the run synced NOTHING. Results are invalid."
      echo "[health] Check: grep 'Cluster name validation' /var/wazuh-manager/logs/wazuh-manager.log"
      echo "[health] (Any 'verify present' below would be against STALE docs — do not trust it.)"
      rc_health=1
    elif [[ "${FAILED:-0}" -gt 0 ]]; then
      echo "[health] WARNING: ${FAILED} sessions failed — the run was disturbed (manager restart,"
      echo "[health] saturation or connection drops). Treat this repetition as TAINTED for the report."
    else
      echo "[health] OK — all ${COMPLETED} sessions completed cleanly."
    fi
  else
    echo "[health] WARNING: no ${bench_csv} — run may have been interrupted."
    rc_health=1
  fi

  if [[ "$EXPECT" != "skip" ]]; then
    echo "[verify] checking case.* on enriched docs (expect all ${EXPECT})..."
    IDX="$IDX" INDEXER_HOST="$INDEXER_HOST" INDEXER_PORT="$INDEXER_PORT" \
    INDEXER_USER="$INDEXER_USER" INDEXER_PASS="$INDEXER_PASS" \
      ./verify_case.sh "${results_dir}/enriched_ids.txt" "$EXPECT" || true
  fi

  return "$rc_health"
}

# --- Repeat loop --------------------------------------------------------------
OVERALL=0
RUN_DIRS=()
for i in $(seq 1 "$REPEATS"); do
  if [[ "$REPEATS" -gt 1 ]]; then run_label="${LABEL}_r${i}"; else run_label="$LABEL"; fi
  hr; echo " Run ${i}/${REPEATS}   → results_${run_label}"; hr
  clean_state
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
