#!/bin/bash
###############################################################################
# run_ci.sh — In-container CI entrypoint for the CodeChecker pipeline.
#
# Starts CodeChecker server on localhost:8001, runs the full scan pipeline,
# generates an HTML report, then stops the server.
#
# Called by `codechecker.sh --scan` and directly by the GitHub Actions
# composite action (.github/actions/codechecker/scan/action.yml).
#
# Required environment variables:
#   SCAN_REF     base ref (tag or SHA)
#   TARGET_REF   target ref (tag or SHA)
#
# Optional:
#   SCAN_TARGET  wazuh make target (default: server)
#   SCAN_NAME    dashboard name for base run
#   TARGET_NAME  dashboard name for target run
#   ENABLE_CTU   cross-translation-unit analysis (default: 1)
#   RUN_INFER    run Infer/RacerD (default: 0; adds ~20 min)
#   RUN_TSAN     run ThreadSanitizer (default: 0; needs kernel tuning)
#   JOBS         parallelism (default: nproc)
###############################################################################
set -u

CC_DB_DIR="${CC_DB_DIR:-/tmp/cc-db}"
CC_HOST="127.0.0.1"
CC_PORT="${CC_PORT:-8001}"
SERVER_URL="http://${CC_HOST}:${CC_PORT}/Default"

SCAN_REF="${SCAN_REF:-}"
TARGET_REF="${TARGET_REF:-}"
SCAN_TARGET="${SCAN_TARGET:-server}"
SCAN_NAME="${SCAN_NAME:-}"
TARGET_NAME="${TARGET_NAME:-}"
ENABLE_CTU="${ENABLE_CTU:-1}"
RUN_INFER="${RUN_INFER:-0}"
RUN_TSAN="${RUN_TSAN:-0}"
JOBS="${JOBS:-$(nproc)}"

SCRIPTS_DIR="${SCRIPTS_DIR:-/cc}"

ok()   { printf '\033[0;32m  [OK]   %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  [WARN] %s\033[0m\n' "$*"; }
step() { printf '\n\033[1;34m=== %s ===\033[0m\n' "$*"; }
die()  { printf '\033[0;31m  [FAIL] %s\033[0m\n' "$*"; exit 1; }

[ -n "$SCAN_REF" ]   || die "SCAN_REF is required"
[ -n "$TARGET_REF" ] || die "TARGET_REF is required"

# ---------------------------------------------------------------------------
# Start CodeChecker server
# ---------------------------------------------------------------------------
step "Starting CodeChecker server on ${CC_HOST}:${CC_PORT}"
mkdir -p "$CC_DB_DIR"
CodeChecker server --workspace "$CC_DB_DIR" --host "$CC_HOST" --port "$CC_PORT" &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true' EXIT INT TERM

for _ in $(seq 1 30); do
    curl -fsS "http://${CC_HOST}:${CC_PORT}/" >/dev/null 2>&1 && break
    sleep 5
done
curl -fsS "http://${CC_HOST}:${CC_PORT}/" >/dev/null 2>&1 \
    && ok "CodeChecker server ready" \
    || die "CodeChecker server did not start within 150 s"

# ---------------------------------------------------------------------------
# Paired differential scan
# ---------------------------------------------------------------------------
step "Paired differential scan (base=$SCAN_REF  target=$TARGET_REF)"
BASE_REF="$SCAN_REF" \
TARGET_REF="$TARGET_REF" \
TARGET="$SCAN_TARGET" \
BASE_NAME="${SCAN_NAME:-wazuh-$SCAN_REF}" \
TARGET_NAME="${TARGET_NAME:-wazuh-$TARGET_REF}" \
SERVER_URL="$SERVER_URL" \
ENABLE_CTU="$ENABLE_CTU" \
JOBS="$JOBS" \
    bash "$SCRIPTS_DIR/run_comparison.sh" \
    || die "run_comparison.sh failed"

# ---------------------------------------------------------------------------
# Optional: Infer/RacerD
# ---------------------------------------------------------------------------
if [ "$RUN_INFER" = "1" ]; then
    step "Infer/RacerD static race scan"
    REF="$TARGET_REF" \
    TARGET="$SCAN_TARGET" \
    RUN_NAME="wazuh-${TARGET_REF}-infer" \
    URL="$SERVER_URL" \
    JOBS="$JOBS" \
        bash "$SCRIPTS_DIR/run_infer.sh" \
        || warn "run_infer.sh returned non-zero (continuing)"
fi

# ---------------------------------------------------------------------------
# Optional: ThreadSanitizer (unit tests + wazuh-db system test)
# ---------------------------------------------------------------------------
if [ "$RUN_TSAN" = "1" ]; then
    step "ThreadSanitizer: unit tests + system test"
    RUN_NAME="wazuh-tsan-${TARGET_REF}" \
    WAZUH_REF="$TARGET_REF" \
    URL="$SERVER_URL" \
    JOBS="$JOBS" \
        bash "$SCRIPTS_DIR/run_tsan_tests.sh" \
        || warn "run_tsan_tests.sh returned non-zero (continuing)"
fi

# ---------------------------------------------------------------------------
# Full HTML report of the target run
# ---------------------------------------------------------------------------
step "Generating full HTML report"
REPORTS_TARGET="/workspace/wazuh/reports_target"
if [ -d "$REPORTS_TARGET" ]; then
    CodeChecker parse "$REPORTS_TARGET" -e html -o "/results/full_report_html" >/dev/null 2>&1 \
        && ok "Full HTML report → /results/full_report_html/" \
        || warn "HTML parse failed (diff HTML still in /results/diff_new_html/)"
else
    warn "reports_target not found — skipping full HTML generation"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
step "Done"
ok "Artifacts in /results/:"
ls -1 /results/ 2>/dev/null | sed 's/^/    /' || true
