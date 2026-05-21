#!/usr/bin/env bash
set -euo pipefail
# ---------------------------------------------------------------------------
# run_benchmark.sh — Orchestrator for Inventory Sync benchmarks.
#
# Starts the resource monitor, runs the benchmark sender with a scenario JSON,
# stops the monitor, and generates charts. All load parameters live inside
# the scenario file — this script is a pure pass-through for the scenario.
#
# Usage:
#   ./run_benchmark.sh --scenario scenarios/baseline.json
#   ./run_benchmark.sh --scenario scenarios/sca_baseline.json --label sca-run1
#   ./run_benchmark.sh --compare results_run1 results_run2
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Added FlatBuffer
PATH="$SCRIPT_DIR/../../../external/flatbuffers/build:$PATH"

# Detect the right Python: prefer VIRTUAL_ENV, then the python3 that has psutil
if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    PYTHON="$VIRTUAL_ENV/bin/python3"
elif python3 -c "import psutil" 2>/dev/null; then
    PYTHON="$(command -v python3)"
else
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
SCENARIO=""
LABEL=""
MANAGER="127.0.0.1"
PORT=1514
REG_PORT=1515
DRAIN_TIMEOUT=60
# Post-run grace — how long monitor.py stays alive after the sender exits,
# so RSS / CPU / disk / queue stats keep being sampled while the system
# settles. CLI default is empty (let scenario decide); resolution order:
#   CLI flag → behavior.post_run_grace → GRACE_TIME (remote only) → 0
POST_RUN_GRACE_CLI=""
CLEANUP_AFTER=false
COMPARE_MODE=false
COMPARE_DIRS=()
CHART_FORMAT="png"
MANAGER_LOG="/var/wazuh-manager/logs/wazuh-manager.log"
GRAPHICS_PY="$SCRIPT_DIR/../../../engine/tools/devContainer/scripts/monitor_graphics_generator.py"
# Remote mode (SSH) settings — activated when MANAGER != 127.0.0.1
SSH_KEY=""
SSH_PORT=22
SSH_PASSWORD=false
INDEXER_PORT=9200
GRACE_TIME=20

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Benchmark mode:
  --scenario FILE         Scenario JSON (required). All load parameters
                          (agent_configs, behavior) live inside the file.
  -l, --label LABEL       Run label for results directory (default: scenario name)
  -m, --manager HOST      Manager address (default: $MANAGER)
  -p, --port PORT         Manager port (default: $PORT)
      --drain-timeout N   (sender-side) seconds stats_collector keeps
                          sampling bench.csv after agents finish, to capture
                          late EndAcks. Default: $DRAIN_TIMEOUT.
      --post-run-grace N  (script-side) seconds to keep monitor.py alive
                          after the sender exits, so RSS / CPU / disk
                          stabilise on the recorded charts. Overrides
                          behavior.post_run_grace from the scenario.
      --cleanup-after     Delete bench-* agents at the end of the run too.
                          By default the post-run cleanup is SKIPPED so the
                          inventory documents survive and can be inspected
                          in the IT Hygiene dashboard. The pre-run cleanup
                          always runs to avoid bench-* accumulation across
                          back-to-back invocations.
      --manager-log PATH  Manager log path for log_parser.py (default: $MANAGER_LOG)

Remote manager (SSH) — activated when --manager is not 127.0.0.1:
      --ssh-key PATH      SSH identity file (default: ssh-agent / system default)
      --ssh-port N        SSH port on the remote manager (default: $SSH_PORT)
      --ssh-password      Prompt for SSH password (requires sshpass installed
                          locally). Mutually exclusive with --ssh-key.
      --indexer-port N    Local wazuh-indexer port to reverse-tunnel so the
                          remote manager can reach it (default: $INDEXER_PORT)
      --grace N           Seconds to wait before sending and after sender
                          finishes, so the manager detects the indexer and
                          queues drain (default: $GRACE_TIME)

Comparison mode:
      --compare DIR...    Compare results from multiple directories
      --format FMT        Chart format: png, svg, pdf (default: $CHART_FORMAT)

  -h, --help              Show this help
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --scenario)       SCENARIO="$2"; shift 2 ;;
        -l|--label)       LABEL="$2"; shift 2 ;;
        -m|--manager)     MANAGER="$2"; shift 2 ;;
        -p|--port)        PORT="$2"; shift 2 ;;
        --drain-timeout)  DRAIN_TIMEOUT="$2"; shift 2 ;;
        --post-run-grace) POST_RUN_GRACE_CLI="$2"; shift 2 ;;
        --cleanup-after)  CLEANUP_AFTER=true; shift ;;
        --manager-log)    MANAGER_LOG="$2"; shift 2 ;;
        --ssh-key)        SSH_KEY="$2"; shift 2 ;;
        --ssh-port)       SSH_PORT="$2"; shift 2 ;;
        --ssh-password)   SSH_PASSWORD=true; shift ;;
        --indexer-port)   INDEXER_PORT="$2"; shift 2 ;;
        --grace)          GRACE_TIME="$2"; shift 2 ;;
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

    "$PYTHON" "$GRAPHICS_PY" \
        $RESULT_ARGS \
        -o "$CHART_DIR" \
        --format "$CHART_FORMAT"

    echo ""
    echo "Charts saved to $CHART_DIR/"
    exit 0
fi

# ---------------------------------------------------------------------------
# Validate scenario
# ---------------------------------------------------------------------------
if [[ -z "$SCENARIO" ]]; then
    echo "Error: --scenario is required."
    usage
    exit 1
fi
if [[ ! -f "$SCENARIO" ]]; then
    echo "Error: scenario file not found: $SCENARIO"
    exit 1
fi

SC_NAME=$("$PYTHON" -c "import json,sys; print(json.load(open('$SCENARIO')).get('name',''))")
[[ -z "$LABEL" && -n "$SC_NAME" ]] && LABEL="$SC_NAME"

# Resolve behavior.post_run_grace from the scenario. Returns empty string
# when the field is missing/null so we can fall back to the per-mode
# default below.
SC_POST_RUN_GRACE=$("$PYTHON" -c "
import json
try:
    v = json.load(open('$SCENARIO')).get('behavior', {}).get('post_run_grace')
    print(int(v) if v is not None else '')
except Exception:
    print('')
")

# ---------------------------------------------------------------------------
# Remote mode detection & SSH setup
# ---------------------------------------------------------------------------
REMOTE_MODE=false
if [[ "$MANAGER" != "127.0.0.1" && "$MANAGER" != "localhost" ]]; then
    REMOTE_MODE=true
fi

REMOTE_MONITOR_DIR="/tmp/wazuh_bench_monitor"
SSH_SOCKET="/tmp/wazuh_bench_ssh_$$"
MONITOR_PY="$SCRIPT_DIR/../../../engine/tools/devContainer/scripts/monitor.py"

_build_ssh_opts() {
    SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o "Port=$SSH_PORT")
    if ! $SSH_PASSWORD; then
        SSH_OPTS+=(-o BatchMode=yes)
    fi
    [[ -n "$SSH_KEY" ]] && SSH_OPTS+=(-i "$SSH_KEY")
    SSH_PREFIX=()
    if $SSH_PASSWORD; then
        SSH_PREFIX=(sshpass -e)
    fi
}

_cleanup_ssh_tunnel() {
    if [[ -S "$SSH_SOCKET" ]]; then
        ssh -S "$SSH_SOCKET" -O exit "root@$MANAGER" 2>/dev/null || true
    fi
}

if $REMOTE_MODE; then
    if $SSH_PASSWORD; then
        if [[ -n "$SSH_KEY" ]]; then
            echo "Error: --ssh-password and --ssh-key are mutually exclusive"
            exit 1
        fi
        if ! command -v sshpass >/dev/null 2>&1; then
            echo "Error: --ssh-password requires 'sshpass' installed locally"
            echo "  Install: apt install sshpass"
            exit 1
        fi
        read -r -s -p "SSH password for root@$MANAGER: " _SSH_PASS
        echo ""
        export SSHPASS="$_SSH_PASS"
        unset _SSH_PASS
    fi

    _build_ssh_opts

    echo ""
    echo "======================================================="
    echo "  Remote Manager Mode"
    echo "======================================================="
    echo ""
    echo "  Manager host:   root@$MANAGER"
    echo "  SSH port:       $SSH_PORT"
    echo "  Auth method:    $($SSH_PASSWORD && echo 'password' || echo 'key/agent')"
    echo "  Indexer port:   $INDEXER_PORT (reverse-tunnel to remote)"
    echo ""

    echo "Checking SSH connectivity..."
    if ! "${SSH_PREFIX[@]}" ssh "${SSH_OPTS[@]}" "root@$MANAGER" "echo ok" >/dev/null 2>&1; then
        echo "Error: Cannot connect via SSH to root@$MANAGER:$SSH_PORT"
        exit 1
    fi
    echo "  SSH connection: OK"

    echo "Checking python3 on remote..."
    REMOTE_PY_VERSION=$("${SSH_PREFIX[@]}" ssh "${SSH_OPTS[@]}" "root@$MANAGER" "python3 --version 2>&1" || true)
    if [[ -z "$REMOTE_PY_VERSION" || "$REMOTE_PY_VERSION" != python* && "$REMOTE_PY_VERSION" != Python* ]]; then
        echo "Error: python3 not found on remote host $MANAGER"
        exit 1
    fi
    echo "  python3: $REMOTE_PY_VERSION"

    echo "Checking psutil on remote..."
    if ! "${SSH_PREFIX[@]}" ssh "${SSH_OPTS[@]}" "root@$MANAGER" "python3 -c 'import psutil'" 2>/dev/null; then
        echo "Error: psutil not available on remote host $MANAGER"
        echo "  Install: pip3 install psutil"
        exit 1
    fi
    echo "  psutil: OK"

    echo "Checking wazuh-manager status on remote..."
    REMOTE_STATUS=$("${SSH_PREFIX[@]}" ssh "${SSH_OPTS[@]}" "root@$MANAGER" \
        "/var/wazuh-manager/bin/wazuh-manager-control status" 2>&1) || true
    if [[ -z "$REMOTE_STATUS" ]] || echo "$REMOTE_STATUS" | grep -q "not running"; then
        echo "Error: wazuh-manager is not fully running on $MANAGER"
        echo "$REMOTE_STATUS"
        exit 1
    fi
    echo "$REMOTE_STATUS" | sed 's/^/    /'

    echo ""
    echo "Deploying monitor.py to remote ($REMOTE_MONITOR_DIR/)..."
    "${SSH_PREFIX[@]}" ssh "${SSH_OPTS[@]}" "root@$MANAGER" "mkdir -p $REMOTE_MONITOR_DIR"
    "${SSH_PREFIX[@]}" scp "${SSH_OPTS[@]}" "$MONITOR_PY" "root@$MANAGER:$REMOTE_MONITOR_DIR/monitor.py" >/dev/null
    echo "  Deployed."

    echo ""
    echo "Opening SSH tunnels..."
    echo "  -L $PORT:localhost:$PORT (agent → manager)"
    echo "  -L $REG_PORT:localhost:$REG_PORT (registration)"
    echo "  -L 55000:localhost:55000 (Wazuh API)"
    echo "  -R $INDEXER_PORT:localhost:$INDEXER_PORT (indexer → remote)"
    "${SSH_PREFIX[@]}" ssh -f -N -M -S "$SSH_SOCKET" "${SSH_OPTS[@]}" \
        -L "$PORT:localhost:$PORT" \
        -L "$REG_PORT:localhost:$REG_PORT" \
        -L "55000:localhost:55000" \
        -R "$INDEXER_PORT:localhost:$INDEXER_PORT" \
        "root@$MANAGER"

    if ! ssh -S "$SSH_SOCKET" -O check "root@$MANAGER" 2>/dev/null; then
        echo "Error: SSH tunnel failed to establish"
        exit 1
    fi
    echo "  Tunnels: OK"

    trap '_cleanup_ssh_tunnel' EXIT

    LOCAL_EPOCH=$(date +%s)
    REMOTE_EPOCH=$(ssh -S "$SSH_SOCKET" "root@$MANAGER" "date +%s")
    TIME_OFFSET=$((REMOTE_EPOCH - LOCAL_EPOCH))
    if [[ ${TIME_OFFSET#-} -gt 2 ]]; then
        echo ""
        _abs_off=${TIME_OFFSET#-}
        _dir="ahead"; (( TIME_OFFSET < 0 )) && _dir="behind"
        echo "  WARNING: Clock offset between local and remote: ${_abs_off}s ${_dir}"
    fi
    echo ""
fi

# ---------------------------------------------------------------------------
# Benchmark mode
# ---------------------------------------------------------------------------

# Create results directory
if [[ -z "$LABEL" ]]; then
    LABEL="$(date +%Y%m%d_%H%M%S)"
fi
RESULTS_DIR="results_${LABEL}"
mkdir -p "$RESULTS_DIR"

BENCH_CSV="$RESULTS_DIR/bench.csv"
SENDER_JSON="$RESULTS_DIR/sender_summary.json"
MONITOR_DIR="$RESULTS_DIR/monitor"
MONITOR_PID_FILE="$RESULTS_DIR/monitor.pid"
SUMMARY_JSON="$RESULTS_DIR/summary.json"
MONITOR_MODULESD_CSV="$MONITOR_DIR/wazuh-manager-modulesd.csv"
DISK_CSV="$MONITOR_DIR/disk_usage.csv"

# Wipe stale outputs from previous runs that reused this label.
rm -f "$BENCH_CSV" "$SENDER_JSON" "$SUMMARY_JSON" "$MONITOR_PID_FILE"
rm -rf "$RESULTS_DIR/charts" "$MONITOR_DIR"

# Copy scenario into the results directory for reproducibility.
cp "$SCENARIO" "$RESULTS_DIR/scenario.json"

echo ""
echo "======================================================="
echo "  Inventory Sync Benchmark"
echo "======================================================="
echo ""
echo "  Scenario:          $SCENARIO"
echo "  Label:             $LABEL"
echo "  Results dir:       $RESULTS_DIR/"
echo "  Manager:           $MANAGER:$PORT"
echo ""

# Run metadata for reproducibility.
cat > "$RESULTS_DIR/params.json" <<PARAMS
{
    "label": "$LABEL",
    "scenario_path": "$SCENARIO",
    "scenario_name": "$SC_NAME",
    "manager": "$MANAGER",
    "port": $PORT,
    "process": "wazuh-manager-modulesd",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
PARAMS

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
mkdir -p "$MONITOR_DIR"

if $REMOTE_MODE; then
    echo "Starting resource monitor on remote ($MANAGER)..."
    REMOTE_OUTPUT_DIR="$REMOTE_MONITOR_DIR/output"
    ssh -S "$SSH_SOCKET" "root@$MANAGER" \
        "mkdir -p $REMOTE_OUTPUT_DIR && python3 $REMOTE_MONITOR_DIR/monitor.py \
            --output-dir $REMOTE_OUTPUT_DIR \
            -s 1.0 \
            --pidfile $REMOTE_MONITOR_DIR/monitor.pid \
            --timeout 30" &
    MONITOR_BG_PID=$!
    sleep 3
    if ! kill -0 "$MONITOR_BG_PID" 2>/dev/null; then
        echo "Error: Remote monitor process failed to start"
        exit 1
    fi
    echo "  Remote monitor PID (local SSH): $MONITOR_BG_PID"
    echo "  Remote output: $REMOTE_OUTPUT_DIR/"
else
    echo "Starting resource monitor (engine/tools/devContainer/scripts/monitor.py)..."
    MONITOR_ARGS=(
        --output-dir "$MONITOR_DIR"
        -s 1.0
        --pidfile "$MONITOR_PID_FILE"
        --timeout 30
    )
    "$PYTHON" "$MONITOR_PY" "${MONITOR_ARGS[@]}" &
    MONITOR_BG_PID=$!
    sleep 3
    if ! kill -0 "$MONITOR_BG_PID" 2>/dev/null; then
        echo "Error: Monitor process failed to start"
        echo "  Make sure the wazuh-manager daemons are running"
        exit 1
    fi
    echo "  Monitor PID: $MONITOR_BG_PID  (output: $MONITOR_DIR/)"
fi

if $REMOTE_MODE && [[ "$GRACE_TIME" -gt 0 ]]; then
    echo ""
    echo "Waiting ${GRACE_TIME}s grace period (manager stabilization + indexer detection)..."
    sleep "$GRACE_TIME"
    echo "  Grace period complete. Starting sender."
fi

# 2. Run benchmark sender (scenario-driven; all load params are in the JSON)
echo ""
echo "Starting benchmark sender..."
echo ""

SENDER_MANAGER="$MANAGER"
if $REMOTE_MODE; then
    SENDER_MANAGER="127.0.0.1"
fi

"$PYTHON" "$SCRIPT_DIR/benchmark_sender_v2.py" \
    --scenario "$SCENARIO" \
    --manager "$SENDER_MANAGER" \
    --port "$PORT" \
    --reg-port "$REG_PORT" \
    --drain-timeout "$DRAIN_TIMEOUT" \
    --summary-json "$SENDER_JSON" \
    -o "$BENCH_CSV" || true

# Post-run grace: keep monitor.py sampling for N more seconds so the
# stabilisation tail (RSS settling, indexer flushing, disk usage growing)
# shows up on the charts. Resolution order:
#   --post-run-grace CLI flag  →  behavior.post_run_grace in scenario  →
#   GRACE_TIME (remote mode default, preserves prior behavior)         →
#   0 (local mode default).
POST_RUN_GRACE=0
if [[ -n "$POST_RUN_GRACE_CLI" ]]; then
    POST_RUN_GRACE="$POST_RUN_GRACE_CLI"
elif [[ -n "$SC_POST_RUN_GRACE" ]]; then
    POST_RUN_GRACE="$SC_POST_RUN_GRACE"
elif $REMOTE_MODE; then
    POST_RUN_GRACE="$GRACE_TIME"
fi

if [[ "$POST_RUN_GRACE" -gt 0 ]]; then
    echo ""
    echo "Waiting ${POST_RUN_GRACE}s post-run grace (monitor keeps sampling)..."
    sleep "$POST_RUN_GRACE"
    echo "  Post-run grace complete."
fi

# 3. Stop monitor & retrieve data
echo ""
echo "Stopping resource monitor..."
if $REMOTE_MODE; then
    REMOTE_PID=$(ssh -S "$SSH_SOCKET" "root@$MANAGER" "cat $REMOTE_MONITOR_DIR/monitor.pid 2>/dev/null" || true)
    if [[ -n "$REMOTE_PID" ]]; then
        ssh -S "$SSH_SOCKET" "root@$MANAGER" "kill -TERM $REMOTE_PID" 2>/dev/null || true
        for i in $(seq 1 15); do
            if ! ssh -S "$SSH_SOCKET" "root@$MANAGER" "kill -0 $REMOTE_PID" 2>/dev/null; then
                break
            fi
            sleep 1
        done
    fi
    kill "$MONITOR_BG_PID" 2>/dev/null || true
    wait "$MONITOR_BG_PID" 2>/dev/null || true
    echo "  Remote monitor stopped"

    echo "Retrieving monitor data from remote..."
    scp -o "ControlPath=$SSH_SOCKET" -o "Port=$SSH_PORT" -r "root@$MANAGER:$REMOTE_OUTPUT_DIR/" "$MONITOR_DIR/" >/dev/null 2>&1
    if [[ -d "$MONITOR_DIR/output" ]]; then
        mv "$MONITOR_DIR/output/"* "$MONITOR_DIR/" 2>/dev/null || true
        rmdir "$MONITOR_DIR/output" 2>/dev/null || true
    fi
    echo "  Retrieved monitor data to $MONITOR_DIR/"
else
    if kill -0 "$MONITOR_BG_PID" 2>/dev/null; then
        kill -TERM "$MONITOR_BG_PID" 2>/dev/null || true
        wait "$MONITOR_BG_PID" 2>/dev/null || true
    fi
    echo "  Monitor stopped"
fi

# 4. Merge CSVs into summary.json (descriptive only — no PASS/FAIL)
echo ""
echo "Generating summary.json..."
SUMMARY_EXTRA=()
[[ -f "$SENDER_JSON" ]] && SUMMARY_EXTRA+=(--sender-json "$SENDER_JSON")
[[ -f "$MONITOR_DIR/logs.csv" ]] && SUMMARY_EXTRA+=(--logs "$MONITOR_DIR/logs.csv")
[[ -f "$RESULTS_DIR/params.json" ]] && SUMMARY_EXTRA+=(--params "$RESULTS_DIR/params.json")

SUMMARY_RC=0
"$PYTHON" "$SCRIPT_DIR/result_summary_v2.py" \
    --bench   "$BENCH_CSV" \
    --monitor "$MONITOR_MODULESD_CSV" \
    --disk-csv "$DISK_CSV" \
    "${SUMMARY_EXTRA[@]}" \
    --out     "$SUMMARY_JSON" || SUMMARY_RC=$?

# 5. Generate charts
echo ""
echo "Generating charts..."
CHART_DIR="$RESULTS_DIR/charts"

"$PYTHON" "$GRAPHICS_PY" \
    -r "$RESULTS_DIR::$LABEL" \
    -o "$CHART_DIR" \
    --format "$CHART_FORMAT" || echo "  Warning: chart generation failed (matplotlib needed)"

# 6. Optional post-run cleanup.
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
echo "  Monitor:   $MONITOR_DIR/"
[[ -f "$MONITOR_DIR/logs.csv" ]] && echo "  Logs:      $MONITOR_DIR/logs.csv"
[[ -f "$SUMMARY_JSON" ]] && echo "  Summary:   $SUMMARY_JSON"
echo "  Charts:    $CHART_DIR/"
echo ""
echo "  To compare with another run:"
echo "    $(basename "$0") --compare $RESULTS_DIR <other_results_dir>"
echo ""
exit $SUMMARY_RC
