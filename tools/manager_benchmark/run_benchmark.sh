#!/usr/bin/env bash
set -euo pipefail
# ---------------------------------------------------------------------------
# run_benchmark.sh — Orchestrate one manager_benchmark run end to end.
#
# Starts the GET /metrics scraper (and, if available, a process-resource
# monitor), runs the Go sender against a scenario in either transport mode,
# stops the helpers, and collates everything into summary.json. All load
# parameters live inside the scenario file — this script only chooses the
# transport, the target, and where the artifacts go.
#
#   uds  mode: POST straight to the module socket (the ingestion pipeline alone)
#   agent mode: enroll against authd, then HTTPS to remoted (the whole relay)
#
# Usage:
#   ./run_benchmark.sh --scenario scenarios/mixed_fleet_windows_linux_uds.json --mode uds
#   ./run_benchmark.sh --scenario scenarios/mixed_fleet_windows_linux.json --mode agent
#
# Agent mode needs the manager configured for open enrollment first:
#   sudo ./prepare_manager.sh
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS_DIR="$SCRIPT_DIR/tool_simulator"
GO_BIN="$TS_DIR/benchmark_sender"

# Defaults
SCENARIO=""
MODE=""                       # empty => take the scenario's own mode
LABEL=""
SOCKET="/var/wazuh-manager/queue/sockets/inventory-sync.sock"
MANAGER="127.0.0.1"
PORT=1517
REG_PORT=1515
SEED=""
DO_METRICS=true
DO_MONITOR=true
DO_CHARTS=true
CLEANUP_AFTER=false
METRICS_INTERVAL=1

MONITOR_PY="$SCRIPT_DIR/../../src/engine/tools/devContainer/scripts/monitor.py"
GRAPHICS_PY="$SCRIPT_DIR/../../src/engine/tools/devContainer/scripts/monitor_graphics_generator.py"

PYTHON="${PYTHON:-python3}"
if [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python3" ]]; then
    PYTHON="$VIRTUAL_ENV/bin/python3"
fi

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --scenario)     SCENARIO="$2"; shift 2 ;;
        --mode)         MODE="$2"; shift 2 ;;
        -l|--label)     LABEL="$2"; shift 2 ;;
        --socket)       SOCKET="$2"; shift 2 ;;
        -m|--manager)   MANAGER="$2"; shift 2 ;;
        -p|--port)      PORT="$2"; shift 2 ;;
        --reg-port)     REG_PORT="$2"; shift 2 ;;
        --seed)         SEED="$2"; shift 2 ;;
        --metrics-interval) METRICS_INTERVAL="$2"; shift 2 ;;
        --no-metrics)   DO_METRICS=false; shift ;;
        --no-monitor)   DO_MONITOR=false; shift ;;
        --no-charts)    DO_CHARTS=false; shift ;;
        --cleanup-after) CLEANUP_AFTER=true; shift ;;
        -h|--help)      usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[[ -z "$SCENARIO" ]] && { echo "Error: --scenario is required." >&2; usage; exit 1; }
[[ -f "$SCENARIO" ]] || { echo "Error: scenario not found: $SCENARIO" >&2; exit 1; }

# Resolve the effective mode: CLI override, else the scenario's own field.
EFFECTIVE_MODE="$MODE"
if [[ -z "$EFFECTIVE_MODE" ]]; then
    EFFECTIVE_MODE=$("$PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("mode",""))' "$SCENARIO")
fi
[[ "$EFFECTIVE_MODE" == "uds" || "$EFFECTIVE_MODE" == "agent" ]] || {
    echo "Error: mode must be uds or agent (got '$EFFECTIVE_MODE'). Set it in the scenario or pass --mode." >&2
    exit 1
}

SC_NAME=$("$PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("name",""))' "$SCENARIO")
[[ -z "$LABEL" ]] && LABEL="${SC_NAME:-$(date +%Y%m%d_%H%M%S)}_${EFFECTIVE_MODE}"

# Build the sender if the binary is missing or stale.
if [[ ! -x "$GO_BIN" || -n "$(find "$TS_DIR" -name '*.go' -newer "$GO_BIN" -print -quit 2>/dev/null)" ]]; then
    echo "Building the sender..."
    ( cd "$TS_DIR" && make build >/dev/null ) || { echo "Error: sender build failed." >&2; exit 1; }
fi

RESULTS_DIR="$SCRIPT_DIR/results_${LABEL}"
mkdir -p "$RESULTS_DIR"
BENCH_CSV="$RESULTS_DIR/bench.csv"
SENDER_JSON="$RESULTS_DIR/sender_summary.json"
SERVER_METRICS_CSV="$RESULTS_DIR/server_metrics.csv"
MONITOR_DIR="$RESULTS_DIR/monitor"
SUMMARY_JSON="$RESULTS_DIR/summary.json"
cp "$SCENARIO" "$RESULTS_DIR/scenario.json"

echo ""
echo "======================================================="
echo "  manager_benchmark"
echo "======================================================="
echo "  scenario:   $SCENARIO ($SC_NAME)"
echo "  mode:       $EFFECTIVE_MODE"
echo "  results:    $RESULTS_DIR/"
[[ "$EFFECTIVE_MODE" == "uds" ]] && echo "  socket:     $SOCKET"
[[ "$EFFECTIVE_MODE" == "agent" ]] && echo "  manager:    $MANAGER:$PORT (reg $REG_PORT)"
echo ""

cat > "$RESULTS_DIR/params.json" <<PARAMS
{
    "label": "$LABEL",
    "scenario_path": "$SCENARIO",
    "scenario_name": "$SC_NAME",
    "mode": "$EFFECTIVE_MODE",
    "manager": "$MANAGER",
    "port": $PORT,
    "socket": "$SOCKET",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
PARAMS

# Pre-run agent cleanup (never touches non-bench agents).
if [[ "$EFFECTIVE_MODE" == "agent" ]]; then
    echo "Cleaning up stale bench-* agents..."
    "$SCRIPT_DIR/cleanup_agents.sh" 2>/dev/null || echo "  (skipped — API not reachable)"
fi

# 1. Start the GET /metrics scraper if the socket is present locally. In agent
#    mode the socket is still local in the devcontainer, so scrape it too.
SCRAPER_PID=""
if $DO_METRICS && [[ -S "$SOCKET" ]]; then
    echo "Scraping GET /metrics ($SOCKET) every ${METRICS_INTERVAL}s..."
    PYTHON="$PYTHON" "$SCRIPT_DIR/scrape_metrics.sh" \
        --socket "$SOCKET" --out "$SERVER_METRICS_CSV" --interval "$METRICS_INTERVAL" &
    SCRAPER_PID=$!
elif $DO_METRICS; then
    echo "Note: metrics socket $SOCKET not present; skipping /metrics scrape."
fi

# 2. Optional process-resource monitor (engine devcontainer tool + psutil).
MONITOR_PID=""
if $DO_MONITOR && [[ -f "$MONITOR_PY" ]] && "$PYTHON" -c 'import psutil' 2>/dev/null; then
    mkdir -p "$MONITOR_DIR"
    echo "Starting process monitor..."
    "$PYTHON" "$MONITOR_PY" --output-dir "$MONITOR_DIR" -s 1.0 \
        --pidfile "$MONITOR_DIR/monitor.pid" --timeout 30 &
    MONITOR_PID=$!
    sleep 2
elif $DO_MONITOR; then
    echo "Note: process monitor unavailable (monitor.py or psutil missing); skipping."
fi

stop_helper() {  # pid
    local pid="$1"
    [[ -n "$pid" ]] || return 0
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}
cleanup_helpers() { stop_helper "$SCRAPER_PID"; stop_helper "$MONITOR_PID"; }
trap cleanup_helpers EXIT

# 3. Run the sender.
echo ""
echo "Running the sender..."
GO_ARGS=(
    --scenario "$SCENARIO"
    --mode "$EFFECTIVE_MODE"
    --socket "$SOCKET"
    --manager "$MANAGER"
    --port "$PORT"
    --reg-port "$REG_PORT"
    --output "$BENCH_CSV"
    --summary-json "$SENDER_JSON"
)
[[ -n "$SEED" ]] && GO_ARGS+=( --seed "$SEED" )
SENDER_RC=0
"$GO_BIN" "${GO_ARGS[@]}" || SENDER_RC=$?

# 4. Stop helpers.
cleanup_helpers
trap - EXIT

# 5. Collate.
echo ""
echo "Generating summary.json..."
SUMMARY_ARGS=( --bench "$BENCH_CSV" --out "$SUMMARY_JSON" )
[[ -f "$SENDER_JSON" ]]         && SUMMARY_ARGS+=( --sender-json "$SENDER_JSON" )
[[ -f "$SERVER_METRICS_CSV" ]]  && SUMMARY_ARGS+=( --server-metrics "$SERVER_METRICS_CSV" )
[[ -f "$MONITOR_DIR/wazuh-manager-modulesd.csv" ]] && SUMMARY_ARGS+=( --monitor "$MONITOR_DIR/wazuh-manager-modulesd.csv" )
[[ -f "$RESULTS_DIR/params.json" ]] && SUMMARY_ARGS+=( --params "$RESULTS_DIR/params.json" )
"$PYTHON" "$SCRIPT_DIR/result_summary.py" "${SUMMARY_ARGS[@]}" || echo "  (summary generation had a warning)"

# 6. Optional charts (best-effort; needs matplotlib).
if $DO_CHARTS && [[ -f "$GRAPHICS_PY" && -d "$MONITOR_DIR" ]]; then
    echo ""
    echo "Generating charts..."
    "$PYTHON" "$GRAPHICS_PY" -r "$RESULTS_DIR::$LABEL" -o "$RESULTS_DIR/charts" --format png \
        || echo "  (chart generation skipped — matplotlib needed)"
fi

# 7. Optional post-run cleanup.
if $CLEANUP_AFTER && [[ "$EFFECTIVE_MODE" == "agent" ]]; then
    echo ""
    echo "Deleting bench-* agents (--cleanup-after)..."
    "$SCRIPT_DIR/cleanup_agents.sh" 2>/dev/null || true
fi

echo ""
echo "======================================================="
echo "  Done — artifacts in $RESULTS_DIR/"
echo "    bench.csv, sender_summary.json, summary.json"
[[ -f "$SERVER_METRICS_CSV" ]] && echo "    server_metrics.csv"
[[ -d "$MONITOR_DIR" ]] && echo "    monitor/"
echo "  Sender exit code: $SENDER_RC ($([[ $SENDER_RC -eq 0 ]] && echo VALID || echo INVALID))"
echo "======================================================="
exit "$SENDER_RC"
