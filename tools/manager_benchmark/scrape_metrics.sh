#!/usr/bin/env bash
set -euo pipefail
# ---------------------------------------------------------------------------
# scrape_metrics.sh — Periodically scrape the inventory_sync_server GET /metrics
# endpoint over its Unix-domain socket into a long-format CSV.
#
# The endpoint (F9a) answers wazuh_metrics::dumpJson of the module's registry:
#   { "name": <daemon>, "timestamp": "...Z",
#     "metrics": [ { "name": ..., "value": N,
#                    "summary": { "count","sum","min","max","p50","p90","p99" } }, ... ] }
#
# Output rows (docu/09 §server_metrics.csv), one per metric per scrape:
#   timestamp,elapsed_s,metric,value
# A histogram contributes one row for its observation count (the metric name)
# plus <name>.count/.sum/.min/.max/.p50/.p90/.p99.
#
# Usage:
#   scrape_metrics.sh --socket PATH --out server_metrics.csv [--interval 1]
# Stops on SIGTERM/SIGINT (the orchestrator kills it when the sender exits).
# ---------------------------------------------------------------------------

SOCKET="/var/wazuh-manager/queue/sockets/inventory-sync.sock"
OUT="server_metrics.csv"
INTERVAL=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --socket)   SOCKET="$2"; shift 2 ;;
        --out)      OUT="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "scrape_metrics: unknown option $1" >&2; exit 1 ;;
    esac
done

PYTHON="${PYTHON:-python3}"

# The flattener reads the /metrics JSON on stdin and appends long-format rows.
# Kept as a -c program (not a heredoc) so the piped body reaches stdin: a
# heredoc would itself claim stdin and the body would never arrive.
read -r -d '' FLATTEN <<'PY' || true
import json, sys
now, elapsed, out = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    doc = json.loads(sys.stdin.read())
except Exception:
    sys.exit(0)
rows = []
for m in doc.get("metrics", []):
    name = m.get("name")
    if name is None:
        continue
    if m.get("value") is not None:
        rows.append((name, m["value"]))
    summ = m.get("summary")
    if isinstance(summ, dict):
        for k in ("count", "sum", "min", "max", "p50", "p90", "p99"):
            if k in summ:
                rows.append((f"{name}.{k}", summ[k]))
with open(out, "a") as fh:
    for metric, value in rows:
        fh.write(f"{now},{elapsed},{metric},{value}\n")
PY

echo "timestamp,elapsed_s,metric,value" > "$OUT"

START=$(date +%s)
running=true
trap 'running=false' TERM INT

while $running; do
    NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    ELAPSED=$(( $(date +%s) - START ))
    # -s: quiet; --max-time keeps a stalled socket from wedging the loop.
    if BODY=$(curl -s --max-time 5 --unix-socket "$SOCKET" http://localhost/metrics 2>/dev/null); then
        printf '%s' "$BODY" | "$PYTHON" -c "$FLATTEN" "$NOW" "$ELAPSED" "$OUT" || true
    fi
    # Sleep in short slices so a stop signal is honored promptly.
    for _ in $(seq 1 "$INTERVAL"); do
        $running || break
        sleep 1
    done
done
