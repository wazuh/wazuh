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

# Added FlatBuffer
PATH="$SCRIPT_DIR/../../../external/flatbuffers/build:$PATH"

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
MANAGER="127.0.0.1"
PORT=1514
REG_PORT=1515
MODULE=""
INDEX=""
PAYLOAD_KIND="package"
PAYLOAD_KIND_FROM_CLI=false
DRAIN_TIMEOUT=60
CLEANUP_AFTER=false
PAYLOAD_SIZE=0
PAD_FIELD=""
DROP_EVERY=0
MAX_EPS=0
SESSIONS_PER_AGENT=0
NO_END=false
USE_DATABATCH=false
BATCH_MAX_BYTES=$((60 * 1024))
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
END_DELAY=1.0
RETRANSMIT=true
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
  -a, --agents N          Number of concurrent agents (default: $AGENTS)
  -d, --data-size N       DataValue messages per session (default: $DATA_SIZE)
  -t, --duration N        Test duration in seconds (default: $DURATION)
  -l, --label LABEL       Run label for results directory (default: timestamp)
  -m, --manager HOST      Manager address (default: $MANAGER)
  -p, --port PORT         Manager port (default: $PORT)
      --payload-kind K    Payload shape: package|system|hotfix|fim_file|sca_check
                          (default: $PAYLOAD_KIND). Automatically selects
                          the consistent module and target index.
      --module NAME       Module name (default: derived from --payload-kind)
      --index NAME        Index name  (default: derived from --payload-kind)
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
      --batch-max-bytes N Estimated bytes cap per DataBatch when
                          --use-databatch is set. Mirrors the real agent's
                          MAX_BATCH_PAYLOAD constant (default: $BATCH_MAX_BYTES bytes
                          = 60 KB).
      --end-delay N       Seconds to sleep between the last DataValue and the
                          End message (default: $END_DELAY). Mirrors the agent
                          sync_end_delay (default 1s). Set to 0 to expose the
                          intra-session race intentionally.
      --no-retransmit     Disable ReqRet handling. Default is retransmit on
                          (matching the real agent); with this flag the first
                          ReqRet aborts the session.
      --max-eps N         Per-agent wire-send rate cap in events/second.
                          Mirrors real syscollector <max_eps> (default 75 on
                          real agents). 0 = no throttle (default: $MAX_EPS).

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
        -a|--agents)      AGENTS="$2"; shift 2 ;;
        -d|--data-size)   DATA_SIZE="$2"; shift 2 ;;
        -t|--duration)    DURATION="$2"; shift 2 ;;
        -l|--label)       LABEL="$2"; shift 2 ;;
        -m|--manager)     MANAGER="$2"; shift 2 ;;
        -p|--port)        PORT="$2"; shift 2 ;;
        --payload-kind)   PAYLOAD_KIND="$2"; PAYLOAD_KIND_FROM_CLI=true; shift 2 ;;
        --module)         MODULE="$2"; shift 2 ;;
        --index)          INDEX="$2"; shift 2 ;;
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
        --max-eps)        MAX_EPS="$2"; shift 2 ;;
        --sessions-per-agent) SESSIONS_PER_AGENT="$2"; shift 2 ;;
        --no-end)         NO_END=true; shift ;;
        --use-databatch)  USE_DATABATCH=true; shift ;;
        --batch-max-bytes) BATCH_MAX_BYTES="$2"; shift 2 ;;
        --end-delay)      END_DELAY="$2"; shift 2 ;;
        --no-retransmit)  RETRANSMIT=false; shift ;;
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
# Remote mode detection & SSH setup
# ---------------------------------------------------------------------------
REMOTE_MODE=false
if [[ "$MANAGER" != "127.0.0.1" && "$MANAGER" != "localhost" ]]; then
    REMOTE_MODE=true
fi

REMOTE_MONITOR_DIR="/tmp/wazuh_bench_monitor"
SSH_SOCKET="/tmp/wazuh_bench_ssh_$$"
MONITOR_PY="$SCRIPT_DIR/../../../engine/tools/devContainer/scripts/monitor.py"
GRAPHICS_PY="$SCRIPT_DIR/../../../engine/tools/devContainer/scripts/monitor_graphics_generator.py"

# Build SSH options array
_build_ssh_opts() {
    SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o "Port=$SSH_PORT")
    if ! $SSH_PASSWORD; then
        SSH_OPTS+=(-o BatchMode=yes)
    fi
    [[ -n "$SSH_KEY" ]] && SSH_OPTS+=(-i "$SSH_KEY")
    # When using password auth, prefix ssh/scp with sshpass -e
    SSH_PREFIX=()
    if $SSH_PASSWORD; then
        SSH_PREFIX=(sshpass -e)
    fi
}

# Cleanup function for SSH tunnel — registered via trap
_cleanup_ssh_tunnel() {
    if [[ -S "$SSH_SOCKET" ]]; then
        ssh -S "$SSH_SOCKET" -O exit "root@$MANAGER" 2>/dev/null || true
    fi
}

if $REMOTE_MODE; then
    # Validate password mode prerequisites
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
        # Prompt for password (hidden input)
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

    # --- Pre-flight: SSH connectivity ---
    echo "Checking SSH connectivity..."
    if ! "${SSH_PREFIX[@]}" ssh "${SSH_OPTS[@]}" "root@$MANAGER" "echo ok" >/dev/null 2>&1; then
        echo "Error: Cannot connect via SSH to root@$MANAGER:$SSH_PORT"
        echo "  Make sure:"
        echo "    - SSH is enabled on the remote host"
        echo "    - root login is permitted (PermitRootLogin yes)"
        echo "    - Your key is authorized (or use --ssh-key / --ssh-password)"
        exit 1
    fi
    echo "  SSH connection: OK"

    # --- Pre-flight: python3 ---
    echo "Checking python3 on remote..."
    REMOTE_PY_VERSION=$("${SSH_PREFIX[@]}" ssh "${SSH_OPTS[@]}" "root@$MANAGER" "python3 --version 2>&1" || true)
    if [[ -z "$REMOTE_PY_VERSION" || "$REMOTE_PY_VERSION" != python* && "$REMOTE_PY_VERSION" != Python* ]]; then
        echo "Error: python3 not found on remote host $MANAGER"
        echo "  Install: apt install python3 python3-pip"
        exit 1
    fi
    echo "  python3: $REMOTE_PY_VERSION"

    # --- Pre-flight: psutil ---
    echo "Checking psutil on remote..."
    if ! "${SSH_PREFIX[@]}" ssh "${SSH_OPTS[@]}" "root@$MANAGER" "python3 -c 'import psutil'" 2>/dev/null; then
        echo "Error: psutil not available on remote host $MANAGER"
        echo "  Install: pip3 install psutil"
        exit 1
    fi
    echo "  psutil: OK"

    # --- Pre-flight: Manager running ---
    echo "Checking wazuh-manager status on remote..."
    REMOTE_STATUS=$("${SSH_PREFIX[@]}" ssh "${SSH_OPTS[@]}" "root@$MANAGER" \
        "/var/wazuh-manager/bin/wazuh-manager-control status" 2>&1) || true
    if [[ -z "$REMOTE_STATUS" ]] || echo "$REMOTE_STATUS" | grep -q "not running"; then
        echo "Error: wazuh-manager is not fully running on $MANAGER"
        echo "$REMOTE_STATUS"
        exit 1
    fi
    echo "$REMOTE_STATUS" | sed 's/^/    /'

    # --- Copy monitor.py to remote ---
    echo ""
    echo "Deploying monitor.py to remote ($REMOTE_MONITOR_DIR/)..."
    "${SSH_PREFIX[@]}" ssh "${SSH_OPTS[@]}" "root@$MANAGER" "mkdir -p $REMOTE_MONITOR_DIR"
    "${SSH_PREFIX[@]}" scp "${SSH_OPTS[@]}" "$MONITOR_PY" "root@$MANAGER:$REMOTE_MONITOR_DIR/monitor.py" >/dev/null
    echo "  Deployed."

    # --- Open persistent SSH tunnel ---
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

    # Verify tunnel is alive
    if ! ssh -S "$SSH_SOCKET" -O check "root@$MANAGER" 2>/dev/null; then
        echo "Error: SSH tunnel failed to establish"
        exit 1
    fi
    echo "  Tunnels: OK"

    # Register cleanup trap (tunnel teardown on exit/error)
    trap '_cleanup_ssh_tunnel' EXIT

    # Capture time offset between local and remote
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
    SC_KIND=$("$PYTHON"  -c "import json,sys; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('payload_kind',''))")
    SC_NAME=$("$PYTHON"  -c "import json,sys; d=json.load(open('$SCENARIO')); print(d.get('name',''))")
    SC_PSIZE=$("$PYTHON" -c "import json,sys; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('payload_size_bytes',''))")
    SC_PFIELD=$("$PYTHON" -c "import json,sys; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('pad_field',''))")
    SC_DROP=$("$PYTHON"  -c "import json,sys; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('drop_every',''))")
    SC_MAXEPS=$("$PYTHON" -c "import json,sys; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('max_eps',''))")
    SC_NOEND=$("$PYTHON" -c "import json,sys; d=json.load(open('$SCENARIO')); v=d.get('load',{}).get('no_end'); print('true' if v is True else ('false' if v is False else ''))")
    SC_DBATCH=$("$PYTHON" -c "import json,sys; d=json.load(open('$SCENARIO')); v=d.get('load',{}).get('use_databatch'); print('true' if v is True else ('false' if v is False else ''))")
    SC_BSIZE=$("$PYTHON" -c "import json,sys; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('batch_max_bytes',''))")
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
    SC_ENDDELAY=$("$PYTHON" -c "import json; d=json.load(open('$SCENARIO')); v=d.get('load',{}).get('end_delay'); print('' if v is None else v)")
    SC_RETX=$("$PYTHON"    -c "import json; d=json.load(open('$SCENARIO')); v=d.get('load',{}).get('retransmit'); print('true' if v is True else ('false' if v is False else ''))")
    SC_SPA=$("$PYTHON" -c "import json; d=json.load(open('$SCENARIO')); print(d.get('load',{}).get('sessions_per_agent',''))")
    [[ -n "$SC_AGENTS" ]] && AGENTS="$SC_AGENTS"
    [[ -n "$SC_DSIZE" ]]  && DATA_SIZE="$SC_DSIZE"
    [[ -n "$SC_DUR" ]]    && DURATION="$SC_DUR"
    [[ -n "$SC_PSIZE" ]]  && PAYLOAD_SIZE="$SC_PSIZE"
    [[ -n "$SC_PFIELD" ]] && PAD_FIELD="$SC_PFIELD"
    [[ -n "$SC_DROP" ]]   && DROP_EVERY="$SC_DROP"
    [[ -n "$SC_MAXEPS" ]] && MAX_EPS="$SC_MAXEPS"
    [[ "$SC_NOEND" == "true" ]]        && NO_END=true
    [[ "$SC_DBATCH" == "true" ]]       && USE_DATABATCH=true
    [[ -n "$SC_BSIZE" ]]               && BATCH_MAX_BYTES="$SC_BSIZE"
    [[ -n "$SC_STYPE" ]]               && SESSION_TYPE="$SC_STYPE"
    [[ -n "$SC_SYNCMODE" ]]            && SYNC_MODE="$SC_SYNCMODE"
    [[ -n "$SC_MCSUM" ]]               && MODULECHECK_CHECKSUM="$SC_MCSUM"
    [[ "$SC_AUTORESYNC" == "true" ]]   && AUTO_RESYNC=true
    [[ -n "$SC_ENDDELAY" ]]            && END_DELAY="$SC_ENDDELAY"
    [[ "$SC_RETX" == "false" ]]        && RETRANSMIT=false
    [[ "$SC_RETX" == "true"  ]]        && RETRANSMIT=true
    [[ -n "$SC_SPA" ]]                 && SESSIONS_PER_AGENT="$SC_SPA"
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
MONITOR_DIR="$RESULTS_DIR/monitor"
MONITOR_PID_FILE="$RESULTS_DIR/monitor.pid"
SUMMARY_JSON="$RESULTS_DIR/summary.json"
# Per-process CSV used by result_summary.py (the IS daemon is modulesd)
MONITOR_MODULESD_CSV="$MONITOR_DIR/wazuh-manager-modulesd.csv"
DISK_CSV="$MONITOR_DIR/disk_usage.csv"

# Wipe stale outputs from previous runs that reused this label.
# The engine monitor (per-process CSVs + disk_usage.csv) writes in append
# mode (useful when run standalone); without this wipe the charts would show
# a diagonal joining the last point of the previous run to t=1 of the new
# one. The sender's bench.csv already truncates on open, but we wipe it too
# for consistency.
rm -f "$BENCH_CSV" "$SENDER_JSON" "$SUMMARY_JSON" "$MONITOR_PID_FILE"
rm -rf "$RESULTS_DIR/charts" "$MONITOR_DIR"

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
    "process": "wazuh-manager-modulesd",
    "payload_size": $PAYLOAD_SIZE,
    "pad_field": "$PAD_FIELD",
    "drop_every": $DROP_EVERY,
    "no_end": $NO_END,
    "use_databatch": $USE_DATABATCH,
    "batch_max_bytes": $BATCH_MAX_BYTES,
    "end_delay": $END_DELAY,
    "retransmit": $RETRANSMIT,
    "max_eps": $MAX_EPS,
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

# 1. Start resource monitor (shared engine/tools monitor.py).
# That monitor writes one CSV per Wazuh manager process plus a separate
# disk_usage.csv into --output-dir. We use the monitor's built-in defaults
# (all Wazuh manager daemons + standard disk paths) so all processes are
# tracked. monitor_graphics_generator.py reads directly from the per-process
# CSV (modulesd) and disk_usage.csv inside monitor/.
mkdir -p "$MONITOR_DIR"

if $REMOTE_MODE; then
    # --- Remote: start monitor.py on the remote manager via SSH ---
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
    # --- Local: start monitor.py directly ---
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

# Grace period: let the manager detect the indexer (reverse tunnel) and stabilize.
if $REMOTE_MODE && [[ "$GRACE_TIME" -gt 0 ]]; then
    echo ""
    echo "Waiting ${GRACE_TIME}s grace period (manager stabilization + indexer detection)..."
    sleep "$GRACE_TIME"
    echo "  Grace period complete. Starting sender."
fi

# 2. Run benchmark sender
echo ""
echo "Starting benchmark sender..."
echo ""

# In remote mode, the sender connects to 127.0.0.1 via the SSH tunnel.
SENDER_MANAGER="$MANAGER"
if $REMOTE_MODE; then
    SENDER_MANAGER="127.0.0.1"
fi

SENDER_ARGS=(
    -a "$AGENTS"
    -d "$DATA_SIZE"
    -t "$DURATION"
    --manager "$SENDER_MANAGER"
    --port "$PORT"
    --reg-port "$REG_PORT"
    --payload-kind "$PAYLOAD_KIND"
    --drain-timeout "$DRAIN_TIMEOUT"
    --summary-json "$SENDER_JSON"
    -o "$BENCH_CSV"
)
[[ -n "$MODULE" ]]                 && SENDER_ARGS+=(--module "$MODULE")
[[ -n "$INDEX"  ]]                 && SENDER_ARGS+=(--index  "$INDEX")
[[ "$PAYLOAD_SIZE" != "0" ]]       && SENDER_ARGS+=(--payload-size "$PAYLOAD_SIZE")
[[ -n "$PAD_FIELD" ]]              && SENDER_ARGS+=(--pad-field    "$PAD_FIELD")
[[ "$DROP_EVERY"   != "0" ]]       && SENDER_ARGS+=(--drop-every   "$DROP_EVERY")
[[ "$MAX_EPS"      != "0" ]]       && SENDER_ARGS+=(--max-eps      "$MAX_EPS")
[[ "$SESSIONS_PER_AGENT" != "0" ]] && SENDER_ARGS+=(--sessions-per-agent "$SESSIONS_PER_AGENT")
[[ "$NO_END"        == "true" ]]   && SENDER_ARGS+=(--no-end)
[[ "$USE_DATABATCH" == "true" ]]   && SENDER_ARGS+=(--use-databatch --batch-max-bytes "$BATCH_MAX_BYTES")
[[ "$SESSION_TYPE" != "delta" ]]   && SENDER_ARGS+=(--session-type "$SESSION_TYPE")
[[ "$SYNC_MODE"    != "1" ]]       && SENDER_ARGS+=(--sync-mode    "$SYNC_MODE")
[[ -n "$MODULECHECK_CHECKSUM" ]]   && SENDER_ARGS+=(--modulecheck-checksum "$MODULECHECK_CHECKSUM")
[[ "$AUTO_RESYNC"  == "true" ]]    && SENDER_ARGS+=(--auto-resync)
SENDER_ARGS+=(--end-delay "$END_DELAY")
[[ "$RETRANSMIT"   == "false" ]]   && SENDER_ARGS+=(--no-retransmit)

# 2b. Schedule scenario `external_actions` as background timer subshells.
# Each fires at `at_sec` seconds from this point (i.e., approximately when the
# sender starts; the sender's own ~70s setup happens AFTER these timers begin,
# so scenarios should set at_sec accounting for that overhead — see
# scenarios/indexer_down_midflight.json for the convention).
# eval is used because cmd is an operator-authored shell command stored in
# the scenario JSON; same trust model as the scenario file itself.
EXT_ACTION_PIDS=()
EXT_ACTION_LOG="$RESULTS_DIR/external_actions.log"
if [[ -n "${SC_EXTACTS:-}" ]]; then
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

# Post-sender grace: let queues drain and indexer process remaining documents.
if $REMOTE_MODE && [[ "$GRACE_TIME" -gt 0 ]]; then
    echo ""
    echo "Waiting ${GRACE_TIME}s post-sender grace (queue drain)..."
    sleep "$GRACE_TIME"
    echo "  Post-sender grace complete."
fi

# 3. Stop monitor & retrieve data
echo ""
echo "Stopping resource monitor..."
if $REMOTE_MODE; then
    # Send SIGTERM to the remote monitor via its pidfile
    REMOTE_PID=$(ssh -S "$SSH_SOCKET" "root@$MANAGER" "cat $REMOTE_MONITOR_DIR/monitor.pid 2>/dev/null" || true)
    if [[ -n "$REMOTE_PID" ]]; then
        ssh -S "$SSH_SOCKET" "root@$MANAGER" "kill -TERM $REMOTE_PID" 2>/dev/null || true
        # Wait for graceful shutdown (log extraction etc.)
        for i in $(seq 1 15); do
            if ! ssh -S "$SSH_SOCKET" "root@$MANAGER" "kill -0 $REMOTE_PID" 2>/dev/null; then
                break
            fi
            sleep 1
        done
    fi
    # Also kill local SSH background process
    kill "$MONITOR_BG_PID" 2>/dev/null || true
    wait "$MONITOR_BG_PID" 2>/dev/null || true
    echo "  Remote monitor stopped"

    # Retrieve results via SCP (use control socket to avoid re-auth)
    echo "Retrieving monitor data from remote..."
    scp -o "ControlPath=$SSH_SOCKET" -o "Port=$SSH_PORT" -r "root@$MANAGER:$REMOTE_OUTPUT_DIR/" "$MONITOR_DIR/" >/dev/null 2>&1
    # Flatten: scp creates output/ subdir — move files up if needed
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

# 4. Merge CSVs into summary.json (PASS/FAIL if scenario provided expectations)
echo ""
echo "Generating summary.json..."
SUMMARY_EXTRA=()
[[ -f "$SENDER_JSON" ]] && SUMMARY_EXTRA+=(--sender-json "$SENDER_JSON")
[[ -f "$MONITOR_DIR/logs.csv" ]] && SUMMARY_EXTRA+=(--logs "$MONITOR_DIR/logs.csv")
[[ -n "$SCENARIO"    ]] && SUMMARY_EXTRA+=(--scenario    "$SCENARIO")
[[ -f "$RESULTS_DIR/params.json" ]] && SUMMARY_EXTRA+=(--params "$RESULTS_DIR/params.json")

SUMMARY_RC=0
"$PYTHON" "$SCRIPT_DIR/result_summary.py" \
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
echo "  Monitor:   $MONITOR_DIR/"
[[ -f "$MONITOR_DIR/logs.csv" ]] && echo "  Logs:      $MONITOR_DIR/logs.csv"
[[ -f "$SUMMARY_JSON" ]] && echo "  Summary:   $SUMMARY_JSON"
echo "  Charts:    $CHART_DIR/"
echo ""
echo "  To compare with another run:"
echo "    $(basename "$0") --compare $RESULTS_DIR <other_results_dir>"
echo ""
exit $SUMMARY_RC
