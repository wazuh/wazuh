#!/usr/bin/env bash
set -euo pipefail
# ---------------------------------------------------------------------------
# run_benchmark.sh — Orchestrator for Inventory Sync benchmarks.
#
# Starts the resource monitor, runs the benchmark sender, stops the monitor,
# and generates comparison charts.
#
# Usage:
#   # Basic run (10 agents, 100 data items, 60s)
#   ./run_benchmark.sh
#
#   # Custom parameters
#   ./run_benchmark.sh -a 50 -d 200 -t 120 --label "baseline"
#
#   # Compare two runs
#   ./run_benchmark.sh --label "no-limits" -a 100 -d 500 -t 60
#   # ... apply queue limit fix ...
#   ./run_benchmark.sh --label "with-limits" -a 100 -d 500 -t 60
#   # Generate comparison charts
#   ./run_benchmark.sh --compare results_no-limits results_with-limits
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Detect the right Python: prefer VIRTUAL_ENV, then the python3 that has psutil
if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    PYTHON="$VIRTUAL_ENV/bin/python3"
elif python3 -c "import psutil" 2>/dev/null; then
    PYTHON="$(command -v python3)"
else
    # Try common devcontainer path
    for candidate in /usr/local/python/current/bin/python3 /usr/bin/python3; do
        if "$candidate" -c "import psutil" 2>/dev/null; then
            PYTHON="$candidate"
            break
        fi
    done
    if [[ -z "${PYTHON:-}" ]]; then
        echo "Error: No python3 with psutil found."
        echo "  Run: pip install -r $SCRIPT_DIR/requirements.txt"
        exit 1
    fi
fi

# Defaults
AGENTS=10
DATA_SIZE=100
DURATION=60
LABEL=""
PROCESS_NAME="wazuh-manager-modulesd"
MANAGER="127.0.0.1"
PORT=1514
REG_PORT=1515
MODULE=""
INDEX=""
PAYLOAD_KIND="package"
PAYLOAD_KIND_FROM_CLI=false
SESSION_DELAY=0
DRAIN_TIMEOUT=60
CLEANUP_AFTER=false
PAYLOAD_SIZE=0
PAD_FIELD=""
DROP_EVERY=0
NO_END=false
USE_DATABATCH=false
BATCH_SIZE=64
# Directories whose disk usage we want to track during the run.
# The Inventory Sync module persists pending DataValues in queue/inventory_sync,
# and queue/engine-output, queue/vd are related manager queues.
DISK_PATHS=(
    "/var/wazuh-manager/queue/inventory_sync"
    "/var/wazuh-manager/queue/engine-output"
    "/var/wazuh-manager/queue/vd"
)
COMPARE_MODE=false
COMPARE_DIRS=()
CHART_FORMAT="png"
SCENARIO=""
MANAGER_LOG="/var/wazuh-manager/logs/wazuh-manager.log"
SESSION_TYPE="delta"
SYNC_MODE=1
MODULECHECK_CHECKSUM=""
AUTO_RESYNC=false

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Benchmark mode:
  -a, --agents N          Number of concurrent agents (default: $AGENTS)
  -d, --data-size N       DataValue messages per session (default: $DATA_SIZE)
  -t, --duration N        Test duration in seconds (default: $DURATION)
  -l, --label LABEL       Run label for results directory (default: timestamp)
  -m, --manager HOST      Manager address (default: $MANAGER)
  -p, --port PORT         Manager port (default: $PORT)
      --process NAME      Process to monitor (default: $PROCESS_NAME)
      --payload-kind K    Payload shape: package|system|hotfix|fim_file|sca_check
                          (default: $PAYLOAD_KIND). Automatically selects
                          the consistent module and target index.
      --module NAME       Module name (default: derived from --payload-kind)
      --index NAME        Index name  (default: derived from --payload-kind)
      --session-delay N   Delay between sessions per agent (default: $SESSION_DELAY)
      --drain-timeout N   Seconds to keep draining in-flight sessions after the
                          duration deadline (default: $DRAIN_TIMEOUT)
      --disk-path PATH    Recursive directory size to track every second.
                          Repeat to track multiple (default: 3 Wazuh queues).
                          Use --disk-path '' once to clear the defaults.
      --cleanup-after     Delete bench-* agents at the end of the run too.
                          By default the post-run cleanup is SKIPPED so the
                          inventory documents survive and can be inspected
                          in the IT Hygiene dashboard. The pre-run cleanup
                          always runs to avoid bench-* accumulation across
                          back-to-back invocations.
      --scenario FILE     Scenario JSON; overrides load params and supplies
                          expectations to result_summary.py
      --manager-log PATH  Manager log path for log_parser.py (default: $MANAGER_LOG)
      --payload-size N    Pad each DataValue payload to >= N bytes (default: 0).
                          Used by large_payload / heavy_payload_burst scenarios.
      --pad-field PATH    Dotted path of the payload field to inflate (e.g.
                          file.path). Default: per --payload-kind. Required if
                          the kind has no default and --payload-size > 0.
      --drop-every N      Skip every Nth DataValue to force ReqRet/missing
                          ranges (default: 0). Used by missing_seq.
      --no-end            Skip End message and EndAck wait; the manager
                          reclaims via session_timeout. Used by no_end.
      --use-databatch     Send DataValues as MessageType_DataBatch instead of
                          one DataValue per message. Used by databatch.
      --batch-size N      DataValues per batch when --use-databatch (default: $BATCH_SIZE).

Comparison mode:
      --compare DIR...    Compare results from multiple directories
      --format FMT        Chart format: png, svg, pdf (default: $CHART_FORMAT)

  -h, --help              Show this help
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--agents)      AGENTS="$2"; shift 2 ;;
        -d|--data-size)   DATA_SIZE="$2"; shift 2 ;;
        -t|--duration)    DURATION="$2"; shift 2 ;;
        -l|--label)       LABEL="$2"; shift 2 ;;
        -m|--manager)     MANAGER="$2"; shift 2 ;;
        -p|--port)        PORT="$2"; shift 2 ;;
        --process)        PROCESS_NAME="$2"; shift 2 ;;
        --payload-kind)   PAYLOAD_KIND="$2"; PAYLOAD_KIND_FROM_CLI=true; shift 2 ;;
        --module)         MODULE="$2"; shift 2 ;;
        --index)          INDEX="$2"; shift 2 ;;
        --session-delay)  SESSION_DELAY="$2"; shift 2 ;;
        --drain-timeout)  DRAIN_TIMEOUT="$2"; shift 2 ;;
        --disk-path)
            # First explicit --disk-path resets the defaults.
            if [[ "${DISK_PATHS_FROM_CLI:-false}" == false ]]; then
                DISK_PATHS=()
                DISK_PATHS_FROM_CLI=true
            fi
            [[ -n "$2" ]] && DISK_PATHS+=("$2")
            shift 2
            ;;
        --cleanup-after)  CLEANUP_AFTER=true; shift ;;
        --scenario)       SCENARIO="$2"; shift 2 ;;
        --manager-log)    MANAGER_LOG="$2"; shift 2 ;;
        --payload-size)   PAYLOAD_SIZE="$2"; shift 2 ;;
        --pad-field)      PAD_FIELD="$2"; shift 2 ;;
        --drop-every)     DROP_EVERY="$2"; shift 2 ;;
        --no-end)         NO_END=true; shift ;;
        --use-databatch)  USE_DATABATCH=true; shift ;;
        --batch-size)     BATCH_SIZE="$2"; shift 2 ;;
        --format)         CHART_FORMAT="$2"; shift 2 ;;
        --compare)
            COMPARE_MODE=true
            shift
            while [[ $# -gt 0 && ! "$1" =~ ^- ]]; do
                COMPARE_DIRS+=("$1")
                shift
            done
            ;;
        -h|--help)        usage; exit 0 ;;
        *)                echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Comparison mode
# ---------------------------------------------------------------------------
if $COMPARE_MODE; then
    if [[ ${#COMPARE_DIRS[@]} -lt 2 ]]; then
        echo "Error: --compare requires at least 2 directories"
        exit 1
    fi

    CHART_DIR="charts_comparison_$(date +%Y%m%d_%H%M%S)"
    RESULT_ARGS=""
    for dir in "${COMPARE_DIRS[@]}"; do
        RESULT_ARGS="$RESULT_ARGS -r $dir"
    done

    echo ""
    echo "Generating comparison charts..."
    echo "  Directories: ${COMPARE_DIRS[*]}"
    echo "  Output:      $CHART_DIR/"
    echo ""

    "$PYTHON" "$SCRIPT_DIR/graphics_generator.py" \
        $RESULT_ARGS \
        -o "$CHART_DIR" \
        --format "$CHART_FORMAT"

    echo ""
    echo "Charts saved to $CHART_DIR/"
    exit 0
fi

# ---------------------------------------------------------------------------
# Benchmark mode
# ---------------------------------------------------------------------------

# If a scenario was provided, override load defaults from its "load" object.
# Expectations live in the JSON and are passed straight to result_summary.py.
if [[ -n "$SCENARIO" ]]; then
    if [[ ! -f "$SCENARIO" ]]; then
        echo "Error: scenario file not found: $SCENARIO"
        exit 1
    fi
    SC_AGENTS=$("$PYTHON" -c "import json,sys; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('agents',''))")
    SC_DSIZE=$("$PYTHON" -c "import json,sys; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('data_size',''))")
    SC_DUR=$("$PYTHON"   -c "import json,sys; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('duration_sec',''))")
    SC_DELAY=$("$PYTHON" -c "import json,sys; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('session_delay',''))")
    SC_KIND=$("$PYTHON"  -c "import json,sys; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('payload_kind',''))")
    SC_NAME=$("$PYTHON"  -c "import json,sys; d=json.load(open('$SCENARIO')); print(d.get('name',''))")
    SC_PSIZE=$("$PYTHON" -c "import json,sys; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('payload_size_bytes',''))")
    SC_PFIELD=$("$PYTHON" -c "import json,sys; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('pad_field',''))")
    SC_DROP=$("$PYTHON"  -c "import json,sys; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('drop_every',''))")
    SC_NOEND=$("$PYTHON" -c "import json,sys; d=json.load(open('$SCENARIO')); v=d.get('load',{}).get('no_end'); print('true' if v is True else ('false' if v is False else ''))")
    SC_DBATCH=$("$PYTHON" -c "import json,sys; d=json.load(open('$SCENARIO')); v=d.get('load',{}).get('use_databatch'); print('true' if v is True else ('false' if v is False else ''))")
    SC_BSIZE=$("$PYTHON" -c "import json,sys; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('batch_size',''))")
    # external_actions are emitted one per line as "at_sec\tcmd" so the bash
    # side can read them with IFS-tab splitting. Embedded tabs and newlines in
    # cmd are sanitized so the protocol stays line-oriented.
    SC_EXTACTS=$("$PYTHON" -c "
import json
d = json.load(open('$SCENARIO'))
for a in d.get('external_actions', []) or []:
    at = a.get('at_sec', 0)
    cmd = (a.get('cmd', '') or '').replace('\t', ' ').replace('\n', ' ')
    print(f'{at}\t{cmd}')
")
    SC_STYPE=$("$PYTHON"   -c "import json; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('session_type',''))")
    SC_SYNCMODE=$("$PYTHON" -c "import json; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('sync_mode',''))")
    SC_MCSUM=$("$PYTHON"   -c "import json; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('modulecheck_checksum',''))")
    SC_AUTORESYNC=$("$PYTHON" -c "import json; d=json.load(open('$SCENARIO')); v=d.get('load',{}).get('auto_resync'); print('true' if v is True else ('false' if v is False else ''))")
    [[ -n "$SC_AGENTS" ]] && AGENTS="$SC_AGENTS"
    [[ -n "$SC_DSIZE" ]]  && DATA_SIZE="$SC_DSIZE"
    [[ -n "$SC_DUR" ]]    && DURATION="$SC_DUR"
    [[ -n "$SC_DELAY" ]]  && SESSION_DELAY="$SC_DELAY"
    [[ -n "$SC_PSIZE" ]]  && PAYLOAD_SIZE="$SC_PSIZE"
    [[ -n "$SC_PFIELD" ]] && PAD_FIELD="$SC_PFIELD"
    [[ -n "$SC_DROP" ]]   && DROP_EVERY="$SC_DROP"
    [[ "$SC_NOEND" == "true" ]]        && NO_END=true
    [[ "$SC_DBATCH" == "true" ]]       && USE_DATABATCH=true
    [[ -n "$SC_BSIZE" ]]               && BATCH_SIZE="$SC_BSIZE"
    [[ -n "$SC_STYPE" ]]               && SESSION_TYPE="$SC_STYPE"
    [[ -n "$SC_SYNCMODE" ]]            && SYNC_MODE="$SC_SYNCMODE"
    [[ -n "$SC_MCSUM" ]]               && MODULECHECK_CHECKSUM="$SC_MCSUM"
    [[ "$SC_AUTORESYNC" == "true" ]]   && AUTO_RESYNC=true
    # CLI wins over the scenario file. If the user did not pass --payload-kind
    # explicitly we adopt whatever the scenario declares.
    if [[ -n "$SC_KIND" && "$PAYLOAD_KIND_FROM_CLI" == false ]]; then
        PAYLOAD_KIND="$SC_KIND"
    fi
    [[ -z "$LABEL" && -n "$SC_NAME" ]] && LABEL="$SC_NAME"
    echo "Scenario loaded: $SCENARIO  (name=$SC_NAME, payload_kind=$PAYLOAD_KIND)"
fi

# Create results directory
if [[ -z "$LABEL" ]]; then
    LABEL="$(date +%Y%m%d_%H%M%S)"
fi
RESULTS_DIR="results_${LABEL}"
mkdir -p "$RESULTS_DIR"

BENCH_CSV="$RESULTS_DIR/bench.csv"
SENDER_JSON="$RESULTS_DIR/sender_summary.json"
MONITOR_CSV="$RESULTS_DIR/monitor.csv"
MONITOR_PID_FILE="$RESULTS_DIR/monitor.pid"
LOGS_CSV="$RESULTS_DIR/logs.csv"
LOG_PARSER_PID_FILE="$RESULTS_DIR/log_parser.pid"
SUMMARY_JSON="$RESULTS_DIR/summary.json"

# Wipe stale outputs from previous runs that reused this label.
# monitor.py and log_parser.py open their CSVs in append mode (useful when
# run standalone); without this rm the charts would show a diagonal joining
# the last point of the previous run to t=1 of the new one. The sender's
# bench.csv already truncates on open, but we wipe it too for consistency.
rm -f "$BENCH_CSV" "$SENDER_JSON" "$MONITOR_CSV" "$LOGS_CSV" "$SUMMARY_JSON" \
      "$MONITOR_PID_FILE" "$LOG_PARSER_PID_FILE"
rm -rf "$RESULTS_DIR/charts"

echo ""
echo "======================================================="
echo "  Inventory Sync Benchmark"
echo "======================================================="
echo ""
echo "  Label:             $LABEL"
echo "  Results dir:       $RESULTS_DIR/"
echo "  Agents:            $AGENTS"
echo "  DataValues/session:$DATA_SIZE"
echo "  Duration:          ${DURATION}s"
echo "  Manager:           $MANAGER:$PORT"
echo "  Module:            $MODULE"
echo "  Process:           $PROCESS_NAME"
echo ""

# Save benchmark parameters for reproducibility
cat > "$RESULTS_DIR/params.json" <<PARAMS
{
    "label": "$LABEL",
    "agents": $AGENTS,
    "data_size": $DATA_SIZE,
    "duration": $DURATION,
    "manager": "$MANAGER",
    "port": $PORT,
    "payload_kind": "$PAYLOAD_KIND",
    "module": "${MODULE:-(from kind)}",
    "index": "${INDEX:-(from kind)}",
    "process": "$PROCESS_NAME",
    "session_delay": $SESSION_DELAY,
    "payload_size": $PAYLOAD_SIZE,
    "pad_field": "$PAD_FIELD",
    "drop_every": $DROP_EVERY,
    "no_end": $NO_END,
    "use_databatch": $USE_DATABATCH,
    "batch_size": $BATCH_SIZE,
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
PARAMS

# Save system info
cat > "$RESULTS_DIR/system_info.txt" <<INFO
Date: $(date -u)
Hostname: $(hostname)
Kernel: $(uname -r)
CPU: $(lscpu 2>/dev/null | grep "Model name" | head -1 | sed 's/Model name:\s*//' || echo "unknown")
Cores: $(nproc 2>/dev/null || echo "unknown")
Memory: $(free -h 2>/dev/null | awk '/^Mem:/ {print $2}' || echo "unknown")
INFO

# 0. Cleanup old benchmark agents
echo "Cleaning up old benchmark agents..."
"$SCRIPT_DIR/cleanup_agents.sh" 2>/dev/null || echo "  (cleanup skipped — API not available)"
echo ""

# 1. Start resource monitor
echo "Starting resource monitor (process: $PROCESS_NAME)..."
MONITOR_ARGS=(
    -n "$PROCESS_NAME"
    -o "$MONITOR_CSV"
    -s 1.0
    --pidfile "$MONITOR_PID_FILE"
)
for p in "${DISK_PATHS[@]}"; do
    [[ -n "$p" ]] && MONITOR_ARGS+=(--disk-path "$p")
done
"$PYTHON" "$SCRIPT_DIR/monitor.py" "${MONITOR_ARGS[@]}" &
MONITOR_BG_PID=$!
sleep 2

if ! kill -0 "$MONITOR_BG_PID" 2>/dev/null; then
    echo "Error: Monitor process failed to start"
    echo "  Make sure '$PROCESS_NAME' is running"
    exit 1
fi
echo "  Monitor PID: $MONITOR_BG_PID"

# 1b. Start manager log parser if the log file exists
LOG_PARSER_BG_PID=""
if [[ -r "$MANAGER_LOG" ]]; then
    echo "Starting manager log parser (log: $MANAGER_LOG)..."
    "$PYTHON" "$SCRIPT_DIR/log_parser.py" \
        --log "$MANAGER_LOG" \
        -o "$LOGS_CSV" \
        -s 1.0 \
        --pidfile "$LOG_PARSER_PID_FILE" &
    LOG_PARSER_BG_PID=$!
    sleep 1
    if kill -0 "$LOG_PARSER_BG_PID" 2>/dev/null; then
        echo "  Log parser PID: $LOG_PARSER_BG_PID"
    else
        echo "  (log parser failed to start; skipping)"
        LOG_PARSER_BG_PID=""
    fi
else
    echo "Manager log not readable at $MANAGER_LOG — skipping log parser"
fi

# 2. Run benchmark sender
echo ""
echo "Starting benchmark sender..."
echo ""

SENDER_ARGS=(
    -a "$AGENTS"
    -d "$DATA_SIZE"
    -t "$DURATION"
    --manager "$MANAGER"
    --port "$PORT"
    --reg-port "$REG_PORT"
    --payload-kind "$PAYLOAD_KIND"
    --session-delay "$SESSION_DELAY"
    --drain-timeout "$DRAIN_TIMEOUT"
    --summary-json "$SENDER_JSON"
    -o "$BENCH_CSV"
)
[[ -n "$MODULE" ]]                 && SENDER_ARGS+=(--module "$MODULE")
[[ -n "$INDEX"  ]]                 && SENDER_ARGS+=(--index  "$INDEX")
[[ "$PAYLOAD_SIZE" != "0" ]]       && SENDER_ARGS+=(--payload-size "$PAYLOAD_SIZE")
[[ -n "$PAD_FIELD" ]]              && SENDER_ARGS+=(--pad-field    "$PAD_FIELD")
[[ "$DROP_EVERY"   != "0" ]]       && SENDER_ARGS+=(--drop-every   "$DROP_EVERY")
[[ "$NO_END"        == "true" ]]   && SENDER_ARGS+=(--no-end)
[[ "$USE_DATABATCH" == "true" ]]   && SENDER_ARGS+=(--use-databatch --batch-size "$BATCH_SIZE")
[[ "$SESSION_TYPE" != "delta" ]]   && SENDER_ARGS+=(--session-type "$SESSION_TYPE")
[[ "$SYNC_MODE"    != "1" ]]       && SENDER_ARGS+=(--sync-mode    "$SYNC_MODE")
[[ -n "$MODULECHECK_CHECKSUM" ]]   && SENDER_ARGS+=(--modulecheck-checksum "$MODULECHECK_CHECKSUM")
[[ "$AUTO_RESYNC"  == "true" ]]    && SENDER_ARGS+=(--auto-resync)

# 2b. Schedule scenario `external_actions` as background timer subshells.
# Each fires at `at_sec` seconds from this point (i.e., approximately when the
# sender starts; the sender's own ~70s setup happens AFTER these timers begin,
# so scenarios should set at_sec accounting for that overhead — see
# scenarios/indexer_down_midflight.json for the convention).
# eval is used because cmd is an operator-authored shell command stored in
# the scenario JSON; same trust model as the scenario file itself.
EXT_ACTION_PIDS=()
EXT_ACTION_LOG="$RESULTS_DIR/external_actions.log"
if [[ -n "$SC_EXTACTS" ]]; then
    : > "$EXT_ACTION_LOG"
    echo "Scheduling external_actions (relative to bench start):"
    while IFS=$'\t' read -r ext_at ext_cmd; do
        [[ -z "$ext_at" || -z "$ext_cmd" ]] && continue
        echo "  T+${ext_at}s: $ext_cmd"
        (
            sleep "$ext_at"
            ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
            echo "[$ts T+${ext_at}s] running: $ext_cmd" | tee -a "$EXT_ACTION_LOG"
            cd "$SCRIPT_DIR" || exit 1
            eval "$ext_cmd" >> "$EXT_ACTION_LOG" 2>&1
            rc=$?
            ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
            echo "[$ts T+${ext_at}s] exit=$rc" | tee -a "$EXT_ACTION_LOG"
        ) &
        EXT_ACTION_PIDS+=($!)
    done <<< "$SC_EXTACTS"
    echo
fi

"$PYTHON" "$SCRIPT_DIR/benchmark_sender.py" "${SENDER_ARGS[@]}" || true

# 2c. Reap any external_action timers that haven't fired yet (e.g. their
# at_sec was longer than the sender's actual runtime).
if [[ ${#EXT_ACTION_PIDS[@]} -gt 0 ]]; then
    for pid in "${EXT_ACTION_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            echo "  (external_action pid=$pid cancelled — sender ended first)"
        else
            wait "$pid" 2>/dev/null || true
        fi
    done
fi

# 3. Stop monitor + log parser
echo ""
echo "Stopping resource monitor..."
if kill -0 "$MONITOR_BG_PID" 2>/dev/null; then
    kill -TERM "$MONITOR_BG_PID" 2>/dev/null || true
    wait "$MONITOR_BG_PID" 2>/dev/null || true
fi
echo "  Monitor stopped"

if [[ -n "$LOG_PARSER_BG_PID" ]] && kill -0 "$LOG_PARSER_BG_PID" 2>/dev/null; then
    echo "Stopping log parser..."
    kill -TERM "$LOG_PARSER_BG_PID" 2>/dev/null || true
    wait "$LOG_PARSER_BG_PID" 2>/dev/null || true
    echo "  Log parser stopped"
fi

# 4. Merge CSVs into summary.json (PASS/FAIL if scenario provided expectations)
echo ""
echo "Generating summary.json..."
SUMMARY_EXTRA=()
[[ -f "$SENDER_JSON" ]] && SUMMARY_EXTRA+=(--sender-json "$SENDER_JSON")
[[ -f "$LOGS_CSV"    ]] && SUMMARY_EXTRA+=(--logs        "$LOGS_CSV")
[[ -n "$SCENARIO"    ]] && SUMMARY_EXTRA+=(--scenario    "$SCENARIO")
[[ -f "$RESULTS_DIR/params.json" ]] && SUMMARY_EXTRA+=(--params "$RESULTS_DIR/params.json")

SUMMARY_RC=0
"$PYTHON" "$SCRIPT_DIR/result_summary.py" \
    --bench   "$BENCH_CSV" \
    --monitor "$MONITOR_CSV" \
    "${SUMMARY_EXTRA[@]}" \
    --out     "$SUMMARY_JSON" || SUMMARY_RC=$?

# 5. Generate charts
echo ""
echo "Generating charts..."
CHART_DIR="$RESULTS_DIR/charts"

"$PYTHON" "$SCRIPT_DIR/graphics_generator.py" \
    -r "$RESULTS_DIR::$LABEL" \
    -o "$CHART_DIR" \
    --format "$CHART_FORMAT" || echo "  Warning: chart generation failed (matplotlib needed)"

# 6. Optional post-run cleanup. By default we keep the bench-* agents alive
#    after the run so the inventory documents they produced remain visible
#    in IT Hygiene; deleting an agent triggers
#    InventorySyncFacade::deleteAgent -> deleteByQuery(wazuh-states-*, agentId)
#    which removes ALL the agent's docs from every wazuh-states-* index.
#    Next invocation will clean them at step 0 anyway.
if $CLEANUP_AFTER; then
    echo ""
    echo "Cleaning up benchmark agents (--cleanup-after)..."
    "$SCRIPT_DIR/cleanup_agents.sh" 2>/dev/null || echo "  (cleanup skipped)"
else
    echo ""
    echo "Skipping post-run cleanup (default). bench-* agents remain registered"
    echo "so their docs stay queryable in the indexer / IT Hygiene dashboard."
    echo "Pass --cleanup-after to delete them at the end of the run."
fi

# 7. Summary
echo ""
echo "======================================================="
echo "  Benchmark Complete"
echo "======================================================="
echo ""
echo "  Results:   $RESULTS_DIR/"
echo "  Bench CSV: $BENCH_CSV"
echo "  Monitor:   $MONITOR_CSV"
[[ -f "$LOGS_CSV"    ]] && echo "  Logs:      $LOGS_CSV"
[[ -f "$SUMMARY_JSON" ]] && echo "  Summary:   $SUMMARY_JSON"
echo "  Charts:    $CHART_DIR/"
echo ""
echo "  To compare with another run:"
echo "    $(basename "$0") --compare $RESULTS_DIR <other_results_dir>"
echo ""
exit $SUMMARY_RC
