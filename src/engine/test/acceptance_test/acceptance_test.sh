#!/bin/bash
# =============================================================================
# acceptance_test.sh – Engine benchmark harness
#
# Runs the wazuh-engine benchmark for each requested thread count.
# For every iteration it:
#   1. Stops the manager (if running).
#   2. Launches analysisd with N orchestrator threads.
#   3. Waits until the engine is ready (log + route check).
#   4. Starts the resource monitor (monitor.py).
#   5. Waits a grace period.
#   6. Runs the benchmark tool (benchmark_tool.go).
#   7. Waits a grace period, then stops monitor & analysisd.
#
# Produces two CSV files per thread count:
#   - monitor-<threads>T.csv    (resource usage)
#   - bench-<threads>T.csv      (EPS / processed)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UTILS_DIR="${SCRIPT_DIR}/utils"

# ---------------------------------------------------------------------------
# Defaults (all overridable via environment or flags)
# ---------------------------------------------------------------------------
: "${WAZUH_HOME:=/var/wazuh-manager}"

# Comma-separated list of thread counts to test (e.g. "1,2,4,8")
: "${THREAD_LIST:=1}"

# Benchmark tool flags
: "${BT_TIME:=10}"          # -t  sending duration (seconds)
: "${BT_RATE:=0}"           # -r  target EPS (0 = unlimited)
: "${BT_BATCH:=50}"         # -b  batch size
: "${BT_INPUT:=${UTILS_DIR}/test_logs}"  # -i  input directory

# Output file watched by the benchmark tool
: "${BT_OUTPUT:=${WAZUH_HOME}/logs/alerts/alerts.json}"

# Grace period (seconds) before & after benchmark
: "${GRACE_SECS:=5}"

# Monitor sampling interval
: "${MONITOR_INTERVAL:=1}"

# Maximum seconds to wait for engine readiness
: "${READY_TIMEOUT:=120}"

# Route name to verify after startup
: "${ROUTE_NAME:=cmsync_standard}"

# Output directory for results
: "${RESULTS_DIR:=${SCRIPT_DIR}/results}"

# Analysisd log file
ANALYSISD_LOG="${WAZUH_HOME}/logs/wazuh-manager.log"

# Analysisd binary
ANALYSISD_BIN="${WAZUH_HOME}/bin/wazuh-manager-analysisd"

# Manager control
MANAGER_CTL="${WAZUH_HOME}/bin/wazuh-manager-control"

# Analysis socket for route check
ANALYSIS_SOCK="${WAZUH_HOME}/queue/sockets/analysis"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "[$(date '+%H:%M:%S')] $*"; }
die()  { log "ERROR: $*"; exit 1; }

stop_manager() {
    if pgrep -x "wazuh-manager-analysisd" > /dev/null 2>&1; then
        log "Stopping manager..."
        "${MANAGER_CTL}" stop 2>/dev/null || true
        # Wait until analysisd is actually gone
        local tries=0
        while pgrep -x "wazuh-manager-analysisd" > /dev/null 2>&1; do
            sleep 1
            tries=$((tries + 1))
            if [[ $tries -ge 30 ]]; then
                log "Force-killing analysisd"
                pkill -9 -x "wazuh-manager-analysisd" || true
                sleep 1
                break
            fi
        done
        log "Manager stopped."
    else
        log "Manager not running."
    fi
}

start_analysisd() {
    local threads="$1"
    log "Starting analysisd with ${threads} orchestrator thread(s)..."

    # Truncate the log so we only see fresh messages
    : > "${ANALYSISD_LOG}"

    WAZUH_ORCHESTRATOR_THREADS="${threads}" "${ANALYSISD_BIN}" &
    ANALYSISD_PID=$!
    log "analysisd launched (PID ${ANALYSISD_PID})."
}

wait_for_ready() {
    local deadline=$((SECONDS + READY_TIMEOUT))
    log "Waiting for engine readiness (timeout ${READY_TIMEOUT}s)..."

    # 1. Wait for the "ready" log line
    while [[ $SECONDS -lt $deadline ]]; do
        if grep -q "Engine started and ready to process events" "${ANALYSISD_LOG}" 2>/dev/null; then
            log "Engine ready (log detected)."
            break
        fi
        sleep 1
    done

    if [[ $SECONDS -ge $deadline ]]; then
        die "Timed out waiting for engine ready log."
    fi

    # 2. Verify route is available
    log "Verifying route '${ROUTE_NAME}'..."
    local resp
    resp=$(curl -s --unix-socket "${ANALYSIS_SOCK}" \
        -X POST http://localhost/router/route/get \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"${ROUTE_NAME}\"}" 2>&1) || true

    if echo "${resp}" | grep -q '"status":"OK"'; then
        log "Route '${ROUTE_NAME}' confirmed: ${resp}"
    else
        die "Route check failed. Response: ${resp}"
    fi
}

start_monitor() {
    local threads="$1"
    local csv_file="${RESULTS_DIR}/monitor-${threads}T.csv"
    local pidfile="${RESULTS_DIR}/monitor-${threads}T.pid"

    log "Starting monitor -> ${csv_file}"
    python3 "${UTILS_DIR}/monitor.py" \
        -n wazuh-manager-analysisd \
        -o "${csv_file}" \
        -s "${MONITOR_INTERVAL}" \
        --pidfile "${pidfile}" &

    MONITOR_PID=$!
    MONITOR_PIDFILE="${pidfile}"
    log "Monitor started (PID ${MONITOR_PID})."
}

stop_monitor() {
    if [[ -n "${MONITOR_PID:-}" ]] && kill -0 "${MONITOR_PID}" 2>/dev/null; then
        log "Stopping monitor (PID ${MONITOR_PID})..."
        kill -INT "${MONITOR_PID}" 2>/dev/null || true
        wait "${MONITOR_PID}" 2>/dev/null || true
        log "Monitor stopped."
    fi
    # Clean up pidfile
    rm -f "${MONITOR_PIDFILE:-}" 2>/dev/null || true
}

run_benchmark() {
    local threads="$1"
    local bench_csv="${RESULTS_DIR}/bench-${threads}T.csv"
    local bench_log="${RESULTS_DIR}/bench-${threads}T.log"

    log "Running benchmark: rate=${BT_RATE} time=${BT_TIME}s batch=${BT_BATCH} input=${BT_INPUT}"
    log "  output watched: ${BT_OUTPUT}"
    log "  csv: ${bench_csv}"

    go run "${UTILS_DIR}/benchmark_tool.go" \
        -i "${BT_INPUT}" \
        -o "${BT_OUTPUT}" \
        -r "${BT_RATE}" \
        -t "${BT_TIME}" \
        -b "${BT_BATCH}" \
        -T \
        -csv "${bench_csv}" \
        2>&1 | tee "${bench_log}"

    log "Benchmark finished."
}

stop_analysisd() {
    log "Stopping analysisd..."
    "${MANAGER_CTL}" stop 2>/dev/null || true
    local tries=0
    while pgrep -x "wazuh-manager-analysisd" > /dev/null 2>&1; do
        sleep 1
        tries=$((tries + 1))
        if [[ $tries -ge 30 ]]; then
            pkill -9 -x "wazuh-manager-analysisd" || true
            break
        fi
    done
    log "analysisd stopped."
}

# ---------------------------------------------------------------------------
# Parse CLI flags (override env defaults)
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --threads LIST    Comma-separated thread counts (default: ${THREAD_LIST})
  --time SECS       Benchmark sending duration   (default: ${BT_TIME})
  --rate EPS        Target EPS, 0=unlimited       (default: ${BT_RATE})
  --batch SIZE      Events per HTTP request        (default: ${BT_BATCH})
  --input DIR       Input logs directory           (default: ${BT_INPUT})
  --output FILE     Output file to watch           (default: ${BT_OUTPUT})
  --grace SECS      Grace period before/after bench(default: ${GRACE_SECS})
  --monitor-interval SECS  Monitor sample interval (default: ${MONITOR_INTERVAL})
  --results DIR     Directory for output CSVs      (default: ${RESULTS_DIR})
  --route NAME      Route name to verify           (default: ${ROUTE_NAME})
  --timeout SECS    Max wait for engine ready      (default: ${READY_TIMEOUT})
  -h, --help        Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --threads)     THREAD_LIST="$2"; shift 2 ;;
        --time)        BT_TIME="$2"; shift 2 ;;
        --rate)        BT_RATE="$2"; shift 2 ;;
        --batch)       BT_BATCH="$2"; shift 2 ;;
        --input)       BT_INPUT="$2"; shift 2 ;;
        --output)      BT_OUTPUT="$2"; shift 2 ;;
        --grace)       GRACE_SECS="$2"; shift 2 ;;
        --monitor-interval) MONITOR_INTERVAL="$2"; shift 2 ;;
        --results)     RESULTS_DIR="$2"; shift 2 ;;
        --route)       ROUTE_NAME="$2"; shift 2 ;;
        --timeout)     READY_TIMEOUT="$2"; shift 2 ;;
        -h|--help)     usage ;;
        *)             die "Unknown option: $1" ;;
    esac
done

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Parse thread list into bash array
IFS=',' read -ra THREADS <<< "${THREAD_LIST}"

mkdir -p "${RESULTS_DIR}"

log "============================================================"
log "  Engine Benchmark Suite"
log "  Threads to test: ${THREADS[*]}"
log "  Results dir:     ${RESULTS_DIR}"
log "============================================================"

for T in "${THREADS[@]}"; do
    log ""
    log "============================================================"
    log "  TEST: ${T} orchestrator thread(s)"
    log "============================================================"

    # Step 1: Stop manager
    stop_manager

    # Step 2: Start analysisd
    start_analysisd "${T}"

    # Step 3: Wait for engine ready
    wait_for_ready

    # Step 4: Start resource monitor
    start_monitor "${T}"

    # Step 5: Grace period before benchmark
    log "Grace period (${GRACE_SECS}s) before benchmark..."
    sleep "${GRACE_SECS}"

    # Step 6: Run benchmark
    run_benchmark "${T}"

    # Step 7: Grace period after benchmark
    log "Grace period (${GRACE_SECS}s) after benchmark..."
    sleep "${GRACE_SECS}"

    # Step 8: Stop monitor & analysisd
    stop_monitor
    stop_analysisd

    log "Test with ${T} thread(s) complete."
    log "  Monitor CSV: ${RESULTS_DIR}/monitor-${T}T.csv"
    log "  Bench CSV:   ${RESULTS_DIR}/bench-${T}T.csv"
done

log ""
log "============================================================"
log "  All tests complete. Results in: ${RESULTS_DIR}/"
log "============================================================"
ls -lh "${RESULTS_DIR}/"
