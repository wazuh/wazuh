#!/usr/bin/env bash
set -euo pipefail
# ---------------------------------------------------------------------------
# scrape_metrics.sh — Poll a module's statistics endpoint into the run's samples file.
#
# A thin wrapper around bench_collect.py, which is THE collector: the same loop, the same
# validation and the same lines that monitor.py's collector threads produce. This script
# exists only because monitor.py needs psutil and this path must work without it; losing
# the process samples to a missing Python package is a fair trade, losing the server's own
# numbers is not.
#
# It used to do the collecting itself, in a curl pipeline with inline Python, and the two
# drifted exactly where it matters: an HTTP 503 with a JSON body was recorded as a
# SUCCESSFUL scrape carrying no metrics (downstream: every counter resets to nothing and
# comes back), a missing socket produced no line at all rather than the failed scrape that
# is the evidence the endpoint was down, the error body was folded into the sample as if it
# were the daemon's own document scalars, and the descriptor manifest was never written.
# Sharing the NDJSON syntax was not the same as sharing the contract, so now it shares the
# implementation.
#
# Output format: see bench_samples.py. One JSON object per scrape, appended, run-marked.
#
# Usage:
#   scrape_metrics.sh --socket PATH --out samples/metrics.ndjson [--interval 1] [--src NAME]
# RUN_LABEL in the environment is recorded in the run marker.
# Stops on SIGTERM/SIGINT (the orchestrator kills it when the sender exits).
# ---------------------------------------------------------------------------

SOCKET=""
OUT="metrics.ndjson"
INTERVAL=1
SRC="inventory-sync"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --socket)   SOCKET="$2"; shift 2 ;;
        --out)      OUT="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --src)      SRC="$2"; shift 2 ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "scrape_metrics: unknown option $1" >&2; exit 1 ;;
    esac
done

PYTHON="${PYTHON:-python3}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTOR="$SCRIPT_DIR/../../src/engine/tools/devContainer/scripts/bench_collect.py"

[[ -f "$COLLECTOR" ]] || { echo "scrape_metrics: collector not found at $COLLECTOR" >&2; exit 1; }

ARGS=( --src "$SRC" --ndjson "$OUT" --interval "$INTERVAL" )
[[ -n "$SOCKET" ]] && ARGS+=( --socket "$SOCKET" )
[[ -n "${RUN_LABEL:-}" ]] && ARGS+=( --run-label "$RUN_LABEL" )

# exec so the orchestrator's SIGTERM reaches the collector rather than this shell.
exec "$PYTHON" "$COLLECTOR" "${ARGS[@]}"
