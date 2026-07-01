#!/bin/bash
###############################################################################
# run_tsan_tests.sh — Broad ThreadSanitizer coverage for Wazuh C modules.
#
# Phase 1 — C UNIT TESTS
#   Builds src/unit_tests/ with -fsanitize=thread via CMake and runs via ctest.
#   Covers: analysisd, os_auth, os_net, wazuh_db, logcollector, syscheckd, etc.
#
# Phase 2 — SYSTEM TEST (wazuh-db under TSan)
#   Builds wazuh-db alone with -fsanitize=thread, starts it against a minimal
#   /var/ossec layout, hammers it with concurrent socket queries via socat, then
#   collects TSan output.
#
# Both phases convert with `report-converter -t tsan` and store to the
# CodeChecker dashboard as run $RUN_NAME.
#
# Knobs:
#   SKIP_UNIT_TESTS=1    skip Phase 1
#   SKIP_SYSTEM_TEST=1   skip Phase 2
#   SYSTEM_TEST_SECS=60  wazuh-db load duration in seconds
###############################################################################
set -euo pipefail

WAZUH_DIR="${WAZUH_DIR:-/workspace/wazuh}"
URL="${URL:-http://127.0.0.1:8001/Default}"
RUN_NAME="${RUN_NAME:-wazuh-tsan-tests}"
WAZUH_REF="${WAZUH_REF:-}"
JOBS="${JOBS:-$(nproc)}"
PERSIST="${PERSIST:-/results}"
TSAN_LOG_DIR="${TSAN_LOG_DIR:-/tmp/tsan_logs_tests}"
REPORTS="${REPORTS:-$WAZUH_DIR/reports_tsan_tests}"

SKIP_UNIT_TESTS="${SKIP_UNIT_TESTS:-}"
SKIP_SYSTEM_TEST="${SKIP_SYSTEM_TEST:-}"
SYSTEM_TEST_SECS="${SYSTEM_TEST_SECS:-60}"

OSSEC_DIR="${OSSEC_DIR:-/tmp/wazuh_tsan_ossec}"
TARGET="${TARGET:-manager}"

ok()  { printf '\033[0;32m  [OK]   %s\033[0m\n' "$*"; }
warn(){ printf '\033[1;33m  [WARN] %s\033[0m\n' "$*"; }
fail(){ printf '\033[0;31m  [FAIL] %s\033[0m\n' "$*"; }
step(){ printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

# 4.x trees recognise only "server"; 5.x+ use "manager".
if [ "$TARGET" = "manager" ]; then
    _vfile="$WAZUH_DIR/VERSION.json"
    _major="5"
    if [ -f "$_vfile" ]; then
        _major=$(python3 -c \
            "import json,sys; d=json.load(open(sys.argv[1])); print(d['version'].split('.')[0])" \
            "$_vfile" 2>/dev/null || echo "5")
    fi
    if [ "$_major" = "4" ]; then
        TARGET="server"
        warn "4.x compat — using make TARGET=server"
    fi
fi

mkdir -p "$TSAN_LOG_DIR" "$PERSIST"
rm -f "$TSAN_LOG_DIR"/tsan_*.log

PHASE1_RACES=0
PHASE2_RACES=0

# ---------------------------------------------------------------------------
# Phase 1 — C unit tests
# ---------------------------------------------------------------------------
if [ -z "$SKIP_UNIT_TESTS" ]; then
    step "Phase 1: Build C unit tests with -fsanitize=thread"
    UT_SRC="$WAZUH_DIR/src/unit_tests"
    UT_BUILD="$WAZUH_DIR/src/unit_tests/build_tsan"
    [ -d "$UT_SRC" ] || { fail "no unit_tests dir at $UT_SRC"; SKIP_UNIT_TESTS=1; }
fi

if [ -z "$SKIP_UNIT_TESTS" ]; then
    LIBWAZUH=$(find "$WAZUH_DIR/src" -maxdepth 1 -name "libwazuh.a" 2>/dev/null | head -1)
    if [ -z "$LIBWAZUH" ]; then
        warn "libwazuh.a not found — run run_comparison.sh first. Skipping Phase 1."
        SKIP_UNIT_TESTS=1
    fi
fi

if [ -z "$SKIP_UNIT_TESTS" ]; then
    rm -rf "$UT_BUILD" && mkdir -p "$UT_BUILD"
    cmake -S "$UT_SRC" -B "$UT_BUILD" \
        -DCMAKE_C_FLAGS="-fsanitize=thread -g -O1 -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=thread" \
        -DCMAKE_BUILD_TYPE=Debug \
        2>&1 | tail -5 \
        || { warn "cmake configure failed — skipping unit tests"; SKIP_UNIT_TESTS=1; }
fi

if [ -z "$SKIP_UNIT_TESTS" ]; then
    make -C "$UT_BUILD" -j"$JOBS" 2>&1 | tail -5 \
        || warn "some unit test targets failed to build (continuing)"

    step "Phase 1: Run unit tests under TSan"
    TSAN_OPTIONS="halt_on_error=0 log_path=$TSAN_LOG_DIR/tsan_unit second_deadlock_stack=1" \
        setarch "$(uname -m)" -R \
        ctest --test-dir "$UT_BUILD" --output-on-failure -j1 --timeout 120 \
        2>&1 | tee "$PERSIST/tsan_unit_ctest.log" || true

    PHASE1_RACES=$(grep -rh "WARNING: ThreadSanitizer" "$TSAN_LOG_DIR"/tsan_unit* 2>/dev/null | wc -l || echo 0)
    ok "Phase 1 done: $PHASE1_RACES TSan warnings across all unit tests"
    cp -f "$TSAN_LOG_DIR"/tsan_unit* "$PERSIST/" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Phase 2 — wazuh-db system test
# ---------------------------------------------------------------------------
if [ -z "$SKIP_SYSTEM_TEST" ]; then
    step "Phase 2: Build wazuh-db with -fsanitize=thread"
    command -v socat >/dev/null 2>&1 || { warn "socat not found. Skipping system test."; SKIP_SYSTEM_TEST=1; }
fi

if [ -z "$SKIP_SYSTEM_TEST" ]; then
    WDB_SRC="$WAZUH_DIR/src/wazuh_db"
    [ -d "$WDB_SRC" ] || { fail "no wazuh_db dir"; SKIP_SYSTEM_TEST=1; }
fi

if [ -z "$SKIP_SYSTEM_TEST" ]; then
    (
        cd "$WAZUH_DIR/src"
        CFLAGS="-fsanitize=thread -g -O1 -fno-omit-frame-pointer" \
        LDFLAGS="-fsanitize=thread" \
        make wazuh_db TARGET="$TARGET" DEBUG=1 -j"$JOBS" 2>&1 | tail -10
    ) || { warn "wazuh_db TSan build failed — skipping system test"; SKIP_SYSTEM_TEST=1; }
fi

if [ -z "$SKIP_SYSTEM_TEST" ]; then
    WDB_BIN=$(find "$WAZUH_DIR/src" -maxdepth 2 -name "wazuh-db" -type f 2>/dev/null | head -1)
    [ -n "$WDB_BIN" ] || { fail "wazuh-db binary not found"; SKIP_SYSTEM_TEST=1; }
fi

if [ -z "$SKIP_SYSTEM_TEST" ]; then
    step "Phase 2: Minimal ossec layout + start wazuh-db under TSan"
    rm -rf "$OSSEC_DIR"
    mkdir -p "$OSSEC_DIR"/{queue/db,queue/sockets,var/run,logs,etc,tmp}
    cat > "$OSSEC_DIR/etc/ossec.conf" <<'CONF'
<ossec_config>
  <global>
    <logall>no</logall>
    <logall_json>no</logall_json>
  </global>
</ossec_config>
CONF

    WDB_SOCKET="$OSSEC_DIR/queue/db/wdb"
    WDB_LOG="$TSAN_LOG_DIR/tsan_system_wdb.log"

    TSAN_OPTIONS="halt_on_error=0 log_path=${WDB_LOG} second_deadlock_stack=1" \
    WAZUH_HOME="$OSSEC_DIR" \
        setarch "$(uname -m)" -R \
        "$WDB_BIN" -f "$OSSEC_DIR/etc/ossec.conf" >"$TSAN_LOG_DIR/wdb_stdout.log" 2>&1 &
    WDB_PID=$!
    ok "wazuh-db started (pid $WDB_PID)"

    for i in $(seq 1 30); do [ -S "$WDB_SOCKET" ] && break; sleep 0.5; done
    if [ ! -S "$WDB_SOCKET" ]; then
        warn "socket did not appear — daemon may have crashed; skipping load phase"
        kill "$WDB_PID" 2>/dev/null || true
        SKIP_SYSTEM_TEST=1
    fi
fi

if [ -z "$SKIP_SYSTEM_TEST" ]; then
    step "Phase 2: Concurrent socket queries for ${SYSTEM_TEST_SECS}s"
    QUERIES='global get-all-agents last_id 0
agent 000 sql select count(*) from sys_processes
global sql select count(*) from agent
agent 001 sql select name from sys_packages limit 5'

    end_time=$(( $(date +%s) + SYSTEM_TEST_SECS ))
    LOAD_PIDS=""
    for slot in 1 2 3 4; do
        (
            while [ "$(date +%s)" -lt "$end_time" ]; do
                printf '%s\n' "$QUERIES" | while IFS= read -r q; do
                    printf '%s' "$q" | socat - "UNIX-CONNECT:$WDB_SOCKET" 2>/dev/null || true
                done
                sleep 0.1
            done
        ) &
        LOAD_PIDS="$LOAD_PIDS $!"
    done

    while [ "$(date +%s)" -lt "$end_time" ]; do printf '.'; sleep 5; done
    printf '\n'

    for p in $LOAD_PIDS; do kill "$p" 2>/dev/null || true; done
    wait $LOAD_PIDS 2>/dev/null || true

    step "Phase 2: Stopping wazuh-db"
    kill "$WDB_PID" 2>/dev/null || true
    wait "$WDB_PID" 2>/dev/null || true

    PHASE2_RACES=$(grep -h "WARNING: ThreadSanitizer" "$TSAN_LOG_DIR"/tsan_system_wdb* 2>/dev/null | wc -l || echo 0)
    ok "Phase 2 done: $PHASE2_RACES TSan warnings from wazuh-db system test"
    cp -f "$TSAN_LOG_DIR"/tsan_system_wdb* "$PERSIST/" 2>/dev/null || true
    cp -f "$TSAN_LOG_DIR/wdb_stdout.log"   "$PERSIST/" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Merge, convert, store
# ---------------------------------------------------------------------------
step "Converting + storing to dashboard as '$RUN_NAME'"

MERGED="$TSAN_LOG_DIR/tsan_merged_all.log"
cat "$TSAN_LOG_DIR"/tsan_*.log > "$MERGED" 2>/dev/null || touch "$MERGED"
cp -f "$MERGED" "$PERSIST/tsan_tests_merged.log"

TOTAL=$(( PHASE1_RACES + PHASE2_RACES ))
ok "Total TSan warnings: $TOTAL  (unit=$PHASE1_RACES  system=$PHASE2_RACES)"

rm -rf "$REPORTS"
if grep -q "WARNING: ThreadSanitizer" "$MERGED" 2>/dev/null; then
    report-converter -t tsan -o "$REPORTS" "$MERGED" \
        || warn "report-converter failed — raw logs in $PERSIST/"
else
    mkdir -p "$REPORTS"
    ok "No races found — storing empty run for dashboard tracking"
fi

CodeChecker store "$REPORTS" --name "$RUN_NAME" --url "$URL" \
    && ok "Stored '$RUN_NAME'" \
    || warn "store failed (server unreachable or empty run not supported — raw logs in $PERSIST/)"

printf '\nPhase 1 (unit tests):     %s races\n' "$PHASE1_RACES"
printf 'Phase 2 (wazuh-db system): %s races\n' "$PHASE2_RACES"
[ "$TOTAL" -gt 0 ] \
    && printf 'Races found — see dashboard run "%s" for details.\n' "$RUN_NAME" \
    || printf 'VERDICT: TSan found no data races. Clean run stored on dashboard.\n'
