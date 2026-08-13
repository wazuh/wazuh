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
#   ./run_benchmark.sh --scenario scenarios/real_syscollector_debian.json --mode uds
#   ./run_benchmark.sh --scenario scenarios/real_syscollector_debian.json --mode agent
#
# The cluster NAME the sessions declare is read from the manager's config (the server
# answers 403 to a foreign cluster); --cluster overrides it, and a remote --manager
# must pass it explicitly. There is no node knob: a session declares no cluster node.
#
# Agent mode needs the manager configured for open enrollment first:
#   sudo ./prepare_manager.sh
#
# --keep-agents (agent mode only): skip the pre-run cleanup of bench-* agents, so a
# previous run's agents AND their indexed documents survive -- e.g. to inspect a
# real_* scenario's data in the indexer's dashboard afterward. Mutually exclusive
# with --cleanup-after. Re-running the SAME scenario/label while agents are still
# kept fails enrollment with "Duplicate agent name" (by design, not silently);
# clean up first with ./cleanup_agents.sh.
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
CLUSTER=""
MANAGER_CONF="/var/wazuh-manager/etc/wazuh-manager.conf"
ENROLL_SETTLE=""
DO_METRICS=true
DO_MONITOR=true
DO_CHARTS=true
CLEANUP_AFTER=false
KEEP_AGENTS=false
METRICS_INTERVAL=1

MONITOR_PY="$SCRIPT_DIR/../../src/engine/tools/devContainer/scripts/monitor.py"
GRAPHICS_PY="$SCRIPT_DIR/../../src/engine/tools/devContainer/scripts/monitor_graphics_generator.py"

PYTHON="${PYTHON:-python3}"
if [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python3" ]]; then
    PYTHON="$VIRTUAL_ENV/bin/python3"
fi

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; }

# Read <cluster><name> out of the manager's config. Scoped to the <cluster> block so
# a <name> elsewhere in the file cannot be picked up by mistake. Prints nothing when
# the file is missing or unreadable, which the caller treats as "not detected" rather
# than as an error.
cluster_name_from_conf() {
    [[ -r "$MANAGER_CONF" ]] || return 0
    sed -n '/<cluster>/,/<\/cluster>/p' "$MANAGER_CONF" 2>/dev/null \
        | sed -n "s:.*<name>\(.*\)</name>.*:\1:p" | head -1
}

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
        --cluster)      CLUSTER="$2"; shift 2 ;;
        --conf)         MANAGER_CONF="$2"; shift 2 ;;
        --enroll-settle) ENROLL_SETTLE="$2"; shift 2 ;;
        --metrics-interval) METRICS_INTERVAL="$2"; shift 2 ;;
        --no-metrics)   DO_METRICS=false; shift ;;
        --no-monitor)   DO_MONITOR=false; shift ;;
        --no-charts)    DO_CHARTS=false; shift ;;
        --cleanup-after) CLEANUP_AFTER=true; shift ;;
        --keep-agents)  KEEP_AGENTS=true; shift ;;
        -h|--help)      usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[[ -z "$SCENARIO" ]] && { echo "Error: --scenario is required." >&2; usage; exit 1; }
[[ -f "$SCENARIO" ]] || { echo "Error: scenario not found: $SCENARIO" >&2; exit 1; }
if $KEEP_AGENTS && $CLEANUP_AFTER; then
    echo "Error: --keep-agents and --cleanup-after contradict each other (keep vs delete)." >&2
    exit 1
fi

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

# Resolve the cluster the sessions will declare. The server answers 403 to a foreign
# cluster, and the value belongs to the manager under test, so read it from that
# manager's own config rather than making every caller repeat it. An explicit
# --cluster always wins; a REMOTE manager is never auto-detected, because the local
# config file then describes a different manager and would be silently wrong.
IS_LOCAL_MANAGER=false
[[ "$MANAGER" == "127.0.0.1" || "$MANAGER" == "localhost" || "$MANAGER" == "::1" ]] && IS_LOCAL_MANAGER=true

if [[ -z "$CLUSTER" ]] && $IS_LOCAL_MANAGER; then
    CLUSTER="$(cluster_name_from_conf)"
    [[ -n "$CLUSTER" ]] && echo "Cluster name not given; using '$CLUSTER' from $MANAGER_CONF"
fi
if [[ -z "$CLUSTER" ]]; then
    echo "Error: could not determine the cluster name." >&2
    if $IS_LOCAL_MANAGER; then
        echo "  $MANAGER_CONF is missing or unreadable (try sudo, or pass --conf/--cluster)." >&2
    else
        echo "  --manager is remote ($MANAGER), so the local config is not consulted." >&2
        echo "  Pass --cluster with the REMOTE manager's <cluster><name>." >&2
    fi
    echo "  Without it every session is answered 403 and the run measures nothing." >&2
    exit 1
fi

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
    "cluster": "$CLUSTER",
    "seed": "$SEED",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
PARAMS

# Pre-run agent cleanup (never touches non-bench agents). Skipped under
# --keep-agents: this is the step that actually destroys a PREVIOUS run's
# agents (and, transitively, its indexed documents) — the enroll-time
# "Duplicate agent name" it exists to avoid is the tradeoff for keeping them.
if [[ "$EFFECTIVE_MODE" == "agent" ]]; then
    if $KEEP_AGENTS; then
        echo "Skipping pre-run cleanup (--keep-agents): a stale bench-* agent from a" \
             "previous kept run will fail enrollment with 'Duplicate agent name'."
    else
        echo "Cleaning up stale bench-* agents..."
        "$SCRIPT_DIR/cleanup_agents.sh" 2>/dev/null || echo "  (skipped — API not reachable)"
    fi
fi

# 1. Process + API monitor. It samples the manager's processes AND polls each
#    daemon's statistics, inventory_sync_server's GET /metrics included, so it is
#    the single poller for a normal run.
MONITOR_PID=""
MONITOR_RUNNING=false
if $DO_MONITOR && [[ -f "$MONITOR_PY" ]] && "$PYTHON" -c 'import psutil' 2>/dev/null; then
    mkdir -p "$MONITOR_DIR"
    echo "Starting process + API monitor..."
    "$PYTHON" "$MONITOR_PY" --output-dir "$MONITOR_DIR" -s 1.0 \
        --pidfile "$MONITOR_DIR/monitor.pid" --timeout 30 &
    MONITOR_PID=$!
    MONITOR_RUNNING=true
    sleep 2
elif $DO_MONITOR; then
    echo "Note: process monitor unavailable (monitor.py or psutil missing)."
fi

# 2. Fallback scraper. Only when the monitor is NOT running: it needs psutil,
#    and losing the server's own numbers because a Python package is missing
#    would be a worse trade than polling the socket from a shell loop.
SCRAPER_PID=""
if $DO_METRICS && ! $MONITOR_RUNNING && [[ -S "$SOCKET" ]]; then
    echo "Monitor unavailable; falling back to scrape_metrics.sh for GET /metrics..."
    PYTHON="$PYTHON" "$SCRIPT_DIR/scrape_metrics.sh" \
        --socket "$SOCKET" --out "$SERVER_METRICS_CSV" --interval "$METRICS_INTERVAL" &
    SCRAPER_PID=$!
elif $DO_METRICS && ! $MONITOR_RUNNING; then
    echo "Note: metrics socket $SOCKET not present; no server metrics for this run."
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
[[ -n "$CLUSTER" ]] && GO_ARGS+=( --cluster "$CLUSTER" )
[[ -n "$ENROLL_SETTLE" ]] && GO_ARGS+=( --enroll-settle "$ENROLL_SETTLE" )
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
# The monitor's wide CSV is preferred; the fallback scraper's long-format file is
# used only when the monitor could not run. result_summary.py detects which is which.
MONITOR_INVSYNC_CSV="$MONITOR_DIR/stats-api-inventory-sync.csv"
if [[ -f "$MONITOR_INVSYNC_CSV" ]]; then
    SUMMARY_ARGS+=( --server-metrics "$MONITOR_INVSYNC_CSV" )
elif [[ -f "$SERVER_METRICS_CSV" ]]; then
    SUMMARY_ARGS+=( --server-metrics "$SERVER_METRICS_CSV" )
fi
[[ -f "$MONITOR_DIR/wazuh-manager-modulesd.csv" ]] && SUMMARY_ARGS+=( --monitor "$MONITOR_DIR/wazuh-manager-modulesd.csv" )
[[ -f "$RESULTS_DIR/params.json" ]] && SUMMARY_ARGS+=( --params "$RESULTS_DIR/params.json" )
"$PYTHON" "$SCRIPT_DIR/result_summary.py" "${SUMMARY_ARGS[@]}" || echo "  (summary generation had a warning)"

# 6. Optional charts (best-effort; needs matplotlib).
if $DO_CHARTS && [[ -f "$GRAPHICS_PY" && -d "$MONITOR_DIR" ]]; then
    echo ""
    echo "Generating charts..."
    # Do not blame matplotlib for every failure: a missing dependency and a real
    # error in the generator look nothing alike, and conflating them sent a
    # KeyError traceback out under the message "matplotlib needed".
    if ! "$PYTHON" -c 'import matplotlib, pandas' 2>/dev/null; then
        echo "  (charts skipped — matplotlib/pandas not installed)"
    elif ! "$PYTHON" "$GRAPHICS_PY" -r "$RESULTS_DIR::$LABEL" -o "$RESULTS_DIR/charts" --format png; then
        echo "  WARNING: chart generation failed (see the traceback above)." >&2
        echo "  The run's data is intact in $RESULTS_DIR; only the charts are missing." >&2
    fi
fi

# 7. Optional post-run cleanup.
if $CLEANUP_AFTER && [[ "$EFFECTIVE_MODE" == "agent" ]]; then
    echo ""
    echo "Deleting bench-* agents (--cleanup-after)..."
    "$SCRIPT_DIR/cleanup_agents.sh" 2>/dev/null || true
elif $KEEP_AGENTS && [[ "$EFFECTIVE_MODE" == "agent" ]]; then
    echo ""
    echo "--keep-agents: this run's bench-* agents (and their indexed documents) were left" \
         "in place for inspection — e.g. in the indexer's dashboard. Delete them with" \
         "./cleanup_agents.sh when done."
fi

echo ""
echo "======================================================="
echo "  Done — artifacts in $RESULTS_DIR/"
echo "    bench.csv, sender_summary.json, summary.json"
[[ -f "$SERVER_METRICS_CSV" ]] && echo "    server_metrics.csv"
[[ -d "$MONITOR_DIR" ]] && echo "    monitor/"
# Sender exit contract: 0 ok, 1 measurement invalid, 2 setup failure,
# 3 measurement VALID but the scenario's expected block failed.
case "$SENDER_RC" in
    0) VERDICT="VALID" ;;
    3) VERDICT="VALID, expected block FAILED (see sender_summary.json)" ;;
    *) VERDICT="INVALID" ;;
esac
echo "  Sender exit code: $SENDER_RC ($VERDICT)"
echo "======================================================="
exit "$SENDER_RC"
