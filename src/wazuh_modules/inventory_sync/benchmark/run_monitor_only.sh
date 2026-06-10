#!/usr/bin/env bash
set -euo pipefail
# ---------------------------------------------------------------------------
# run_monitor_only.sh — Capture manager-side metrics during a real-agent test.
#
# Sister script to run_benchmark.sh: same monitor + log_parser + charts setup,
# but NO sender (the load comes from real Wazuh agents you start separately).
#
# Workflow:
#   1. Run this script on the MANAGER host BEFORE starting the agents:
#        ./run_monitor_only.sh --label real_agents_4
#   2. The script wipes stale outputs, starts the engine monitor + log_parser
#      in the background, and waits.
#   3. Start your 4 real Wazuh agents (or restart them after clearing their
#      syscollector DB to force a first-sync).
#   4. The script auto-stops when the manager has been idle (workers_q == 0
#      AND indexer_q == 0 AND sessions == 0) for --auto-stop-after seconds.
#      Or you can Ctrl+C at any time; cleanup runs.
#   5. monitor.csv (legacy merged) + logs.csv + charts get produced under
#      results_<label>/, ready for ./run_benchmark.sh --compare.
#
# Usage:
#   ./run_monitor_only.sh                                 # label=monitor_<ts>, duration=600s
#   ./run_monitor_only.sh --label real_agents_4 -t 300
#   ./run_monitor_only.sh --label real_agents_4 --auto-stop-after 60
#   ./run_monitor_only.sh --label real_agents_4 --no-auto-stop -t 1200
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Detect Python with psutil — same resolution order as run_benchmark.sh:
#   1. Active venv (VIRTUAL_ENV)
#   2. setup_monitor.sh venv (/opt/wazuh-monitor-venv)
#   3. System python3 that already has psutil
#   4. Known alternative paths
if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    PYTHON="$VIRTUAL_ENV/bin/python3"
elif [[ -x "/opt/wazuh-monitor-venv/bin/python3" ]]; then
    PYTHON="/opt/wazuh-monitor-venv/bin/python3"
elif python3 -c "import psutil" 2>/dev/null; then
    PYTHON="$(command -v python3)"
else
    for candidate in /usr/local/python/current/bin/python3 /usr/bin/python3; do
        if "$candidate" -c "import psutil" 2>/dev/null; then
            PYTHON="$candidate"; break
        fi
    done
    if [[ -z "${PYTHON:-}" ]]; then
        echo "Error: No python3 with psutil found." >&2
        echo "  Run: $(dirname "${BASH_SOURCE[0]}")/../../../engine/tools/devContainer/scripts/setup_monitor.sh" >&2
        exit 1
    fi
fi

# Defaults
LABEL=""
DURATION=600
AUTO_STOP_AFTER=60
PROCESS_NAME="wazuh-manager-modulesd"
MANAGER_LOG="/var/wazuh-manager/logs/wazuh-manager.log"
DISK_PATHS=(
    "/var/wazuh-manager/queue/inventory_sync"
    "/var/wazuh-manager/queue/engine-output"
    "/var/wazuh-manager/queue/vd"
)

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]
  -l, --label LABEL          Results directory label (default: monitor_<timestamp>)
  -t, --duration N           Maximum duration in seconds (default: $DURATION)
      --auto-stop-after N    Stop early after N idle seconds in a row
                             (workers_q=indexer_q=sessions=0). 0 to disable.
                             Default: $AUTO_STOP_AFTER
      --no-auto-stop         Alias for --auto-stop-after 0
      --process NAME         Process to monitor (default: $PROCESS_NAME)
      --manager-log PATH     Manager log path (default: $MANAGER_LOG)
      --disk-path PATH       Recursive directory size to track. Repeat for
                             multiple. Default: 3 Wazuh queues.
  -h, --help                 Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -l|--label)            LABEL="$2"; shift 2 ;;
        -t|--duration)         DURATION="$2"; shift 2 ;;
        --auto-stop-after)     AUTO_STOP_AFTER="$2"; shift 2 ;;
        --no-auto-stop)        AUTO_STOP_AFTER=0; shift ;;
        --process)             PROCESS_NAME="$2"; shift 2 ;;
        --manager-log)         MANAGER_LOG="$2"; shift 2 ;;
        --disk-path)
            if [[ "${DISK_PATHS_FROM_CLI:-false}" == false ]]; then
                DISK_PATHS=(); DISK_PATHS_FROM_CLI=true
            fi
            [[ -n "$2" ]] && DISK_PATHS+=("$2")
            shift 2
            ;;
        -h|--help)             usage; exit 0 ;;
        *)                     echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[[ -z "$LABEL" ]] && LABEL="monitor_$(date +%Y%m%d_%H%M%S)"
RESULTS_DIR="results_${LABEL}"
mkdir -p "$RESULTS_DIR"

MONITOR_CSV="$RESULTS_DIR/monitor.csv"
MONITOR_DIR="$RESULTS_DIR/monitor"
MONITOR_PID_FILE="$RESULTS_DIR/monitor.pid"
LOGS_CSV="$RESULTS_DIR/logs.csv"
LOG_PARSER_PID_FILE="$RESULTS_DIR/log_parser.pid"

# Wipe stale outputs from previous runs that reused this label.
rm -f "$MONITOR_CSV" "$LOGS_CSV" "$MONITOR_PID_FILE" "$LOG_PARSER_PID_FILE"
rm -rf "$RESULTS_DIR/charts" "$MONITOR_DIR"
mkdir -p "$MONITOR_DIR"

cat <<EOF

=======================================================
  Monitor-only mode (real-agent capture)
=======================================================
  Label:              $LABEL
  Results dir:        $RESULTS_DIR/
  Process:            $PROCESS_NAME
  Max duration:       ${DURATION}s
  Auto-stop after:    ${AUTO_STOP_AFTER}s of idle (0 = disabled)
  Manager log:        $MANAGER_LOG
  Disk paths:         ${DISK_PATHS[*]}

EOF

# Save params for reproducibility (same shape as run_benchmark.sh).
cat > "$RESULTS_DIR/params.json" <<PARAMS
{
    "label": "$LABEL",
    "mode": "monitor_only",
    "duration": $DURATION,
    "auto_stop_after": $AUTO_STOP_AFTER,
    "process": "$PROCESS_NAME",
    "manager_log": "$MANAGER_LOG",
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

# Cleanup hook: stop background processes if we exit early (Ctrl+C, error).
cleanup() {
    local pid
    for pid_file in "$MONITOR_PID_FILE" "$LOG_PARSER_PID_FILE"; do
        if [[ -f "$pid_file" ]]; then
            pid=$(cat "$pid_file" 2>/dev/null || true)
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                kill -TERM "$pid" 2>/dev/null || true
            fi
        fi
    done
}
trap cleanup EXIT INT TERM

# 1. Start resource monitor.
MONITOR_PY="$SCRIPT_DIR/../../../engine/tools/devContainer/scripts/monitor.py"
echo "Starting resource monitor..."
MONITOR_ARGS=(
    --exe "/var/wazuh-manager/bin/$PROCESS_NAME"
    --output-dir "$MONITOR_DIR"
    -s 1.0
    --pidfile "$MONITOR_PID_FILE"
    --timeout 30
)
for p in "${DISK_PATHS[@]}"; do
    [[ -n "$p" ]] && MONITOR_ARGS+=(--disk-path "$p")
done
"$PYTHON" "$MONITOR_PY" "${MONITOR_ARGS[@]}" >"$RESULTS_DIR/monitor.log" 2>&1 &
MONITOR_BG_PID=$!
sleep 3

if ! kill -0 "$MONITOR_BG_PID" 2>/dev/null; then
    echo "Error: monitor failed to start. See $RESULTS_DIR/monitor.log" >&2
    exit 1
fi
echo "  Monitor PID: $MONITOR_BG_PID  (output: $MONITOR_DIR/)"

# 2. Start log parser if the manager log is readable.
LOG_PARSER_BG_PID=""
if [[ -r "$MANAGER_LOG" ]]; then
    echo "Starting log parser..."
    "$PYTHON" "$SCRIPT_DIR/log_parser.py" \
        --log "$MANAGER_LOG" \
        -o "$LOGS_CSV" \
        -s 1.0 \
        --pidfile "$LOG_PARSER_PID_FILE" >"$RESULTS_DIR/log_parser.log" 2>&1 &
    LOG_PARSER_BG_PID=$!
    sleep 1
    if kill -0 "$LOG_PARSER_BG_PID" 2>/dev/null; then
        echo "  Log parser PID: $LOG_PARSER_BG_PID"
    else
        echo "  (log parser failed to start; auto-stop disabled)"
        LOG_PARSER_BG_PID=""
        AUTO_STOP_AFTER=0
    fi
else
    echo "Manager log not readable at $MANAGER_LOG — log parser skipped."
    echo "Auto-stop disabled (needs queue stats from logs.csv)."
    AUTO_STOP_AFTER=0
fi

cat <<EOF

=======================================================
  READY. Start your real agents now (or restart them).
=======================================================

EOF

# 3. Poll for completion: either max duration or idle for AUTO_STOP_AFTER s.
start_time=$(date +%s)
idle_streak=0
prev_progress=""

while true; do
    sleep 5
    now=$(date +%s)
    elapsed=$(( now - start_time ))

    if (( elapsed >= DURATION )); then
        echo "Max duration ${DURATION}s reached — stopping."
        break
    fi

    # If auto-stop is enabled and logs.csv exists, check idleness.
    if (( AUTO_STOP_AFTER > 0 )) && [[ -f "$LOGS_CSV" ]]; then
        idle=$("$PYTHON" - "$LOGS_CSV" <<'PYIDLE'
import csv, sys
try:
    with open(sys.argv[1]) as f:
        rows = list(csv.DictReader(f))
except FileNotFoundError:
    print("unknown")
    sys.exit()
if not rows:
    print("unknown"); sys.exit()
# Look at the last 5 rows; require ALL of them to be idle to avoid flapping.
recent = rows[-5:]
def n(row, key):
    v = (row.get(key) or "").strip()
    try:
        return int(v)
    except (ValueError, TypeError):
        return -1  # unknown → treat as not-idle
busy = False
for r in recent:
    if n(r, "workers_q") > 0 or n(r, "indexer_q") > 0 or n(r, "sessions") > 0:
        busy = True; break
if any(n(r, "workers_q") < 0 for r in recent):
    print("unknown")
else:
    print("idle" if not busy else "busy")
PYIDLE
)

        case "$idle" in
            idle)
                idle_streak=$((idle_streak + 5))
                progress="idle for ${idle_streak}s / ${AUTO_STOP_AFTER}s threshold (elapsed=${elapsed}s)"
                if (( idle_streak >= AUTO_STOP_AFTER )); then
                    echo
                    echo "Manager idle for ${idle_streak}s — auto-stopping."
                    break
                fi
                ;;
            busy)
                idle_streak=0
                progress="busy (elapsed=${elapsed}s)"
                ;;
            *)
                progress="waiting for queue stats from manager log... (elapsed=${elapsed}s)"
                ;;
        esac

        if [[ "$progress" != "$prev_progress" ]]; then
            echo "  [$progress]"
            prev_progress="$progress"
        fi
    else
        echo "  [elapsed=${elapsed}s / ${DURATION}s — auto-stop off, waiting for --duration]"
    fi
done

# 4. Stop background processes.
echo
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

# Clear the EXIT trap now that we've stopped cleanly — otherwise it would
# fire again and try to kill already-stopped PIDs.
trap - EXIT INT TERM

# 5. Merge legacy monitor.csv (same logic as run_benchmark.sh).
"$PYTHON" - "$MONITOR_DIR" "$MONITOR_CSV" "$PROCESS_NAME" <<'PYMERGE' || true
import csv, sys
from pathlib import Path

monitor_dir = Path(sys.argv[1])
out_csv = Path(sys.argv[2])
process_name = sys.argv[3]

proc_csv = monitor_dir / f"{process_name}.csv"
disk_csv = monitor_dir / "disk_usage.csv"
if not proc_csv.is_file():
    print(f"warning: {proc_csv} not found, skipping merge", file=sys.stderr)
    sys.exit(0)

disk_by_ts = {}; disk_cols = []
if disk_csv.is_file():
    with open(disk_csv) as f:
        r = csv.DictReader(f)
        disk_cols = [c for c in (r.fieldnames or [])
                     if c.startswith("dir_") and c.endswith("_mb")]
        for row in r:
            if row.get("timestamp"):
                disk_by_ts[row["timestamp"]] = row

last_seen = {c: "0.0" for c in disk_cols}
total = unmatched = 0
with open(proc_csv) as fin, open(out_csv, "w", newline="") as fout:
    r = csv.DictReader(fin)
    fn = list(r.fieldnames or []) + disk_cols
    w = csv.DictWriter(fout, fieldnames=fn); w.writeheader()
    for row in r:
        total += 1
        d = disk_by_ts.get(row.get("timestamp", ""))
        if d is None:
            unmatched += 1
            for c in disk_cols: row[c] = last_seen[c]
        else:
            for c in disk_cols:
                last_seen[c] = d.get(c, last_seen[c])
                row[c] = last_seen[c]
        w.writerow(row)
print(f"merged -> {out_csv}  ({total} rows, {unmatched} carry-forward)")
PYMERGE

# 6. Generate charts using the shared engine monitor_graphics_generator.py.
# That generator does auto-discovery of per-process CSVs, reads
# disk_usage.csv directly, and parses invsync_queue_stats.csv /
# invsync_session_stats.csv. We feed it $MONITOR_DIR (already has the
# per-process CSVs and disk_usage.csv) plus a symlink from logs.csv so the
# InventorySync queue chart section kicks in.
ENGINE_GFX="$SCRIPT_DIR/../../../engine/tools/devContainer/scripts/monitor_graphics_generator.py"
if [[ ! -f "$ENGINE_GFX" ]]; then
    echo "warning: engine monitor_graphics_generator.py not found at $ENGINE_GFX" >&2
    echo "         falling back to benchmark/graphics_generator.py"
    ENGINE_GFX="$SCRIPT_DIR/graphics_generator.py"
fi

# Expose logs.csv as the file name the engine generator expects.
# It only reads the queue-stats columns from it (workers_q, indexer_q,
# sessions, ...) so extra error-counter columns are ignored.
if [[ -f "$LOGS_CSV" ]] && [[ ! -e "$MONITOR_DIR/invsync_queue_stats.csv" ]]; then
    ln -sf "$(readlink -f "$LOGS_CSV")" "$MONITOR_DIR/invsync_queue_stats.csv"
fi

echo
echo "Generating charts (engine monitor_graphics_generator.py)..."
"$PYTHON" "$ENGINE_GFX" \
    -r "$MONITOR_DIR::$LABEL" \
    -o "$RESULTS_DIR/charts" \
    --format png || true

cat <<EOF

=======================================================
  Done.
=======================================================
  Results:   $RESULTS_DIR/
  Monitor:   $MONITOR_CSV  (+ $MONITOR_DIR/*.csv)
  Logs:      $LOGS_CSV
  Charts:    $RESULTS_DIR/charts/

To compare against a bench run:
  ./run_benchmark.sh --compare results_<bench_label> $RESULTS_DIR

EOF
