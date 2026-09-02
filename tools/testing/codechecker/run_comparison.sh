#!/bin/bash
###############################################################################
# run_comparison.sh — CodeChecker differential static-analysis scan.
#
# Compares two Wazuh refs (tags, branches or SHAs) and stores both runs to the
# CodeChecker dashboard for a visual diff.  Designed to run INSIDE the
# codechecker Docker container (see tools/testing/codechecker/Dockerfile).
#
# Workflow:
#   1. Clone wazuh (cached — clone once, reused across runs).
#   2. BASE  scan: checkout BASE_REF  -> make deps + build -> log -> analyze.
#   3. TARGET scan: checkout TARGET_REF -> make deps + build -> log -> analyze.
#   4. DIFF (CLI): cmd diff --new / --resolved / --unresolved -> /results/*.txt.
#   5. STORE both runs to the server while the tree still matches each ref.
#   6. Mirror compile_commands + summaries to /results/.
###############################################################################
set -u

TARGET="${TARGET:-agent}"
BASE_REF="${BASE_REF:-}"
TARGET_REF="${TARGET_REF:-}"
REPO_URL="${REPO_URL:-https://github.com/wazuh/wazuh.git}"
SCAN_ONLY="${SCAN_ONLY:-}"

BASE_NAME="${BASE_NAME:-wazuh-$BASE_REF}"
TARGET_NAME="${TARGET_NAME:-wazuh-$TARGET_REF}"

case "$BASE_NAME"   in *-agent|*-server|*-winagent|*-manager|*-local) ;; *) BASE_NAME="$BASE_NAME-$TARGET";;   esac
case "$TARGET_NAME" in *-agent|*-server|*-winagent|*-manager|*-local) ;; *) TARGET_NAME="$TARGET_NAME-$TARGET";; esac

WORKSPACE="${WORKSPACE:-/workspace}"
WAZUH_DIR="${WAZUH_DIR:-$WORKSPACE/wazuh}"
RESULTS_DIR="${RESULTS_DIR:-/results}"
SERVER_URL="${SERVER_URL:-http://127.0.0.1:8001/Default}"
HOST_UI_URL="${HOST_UI_URL:-http://localhost:8001}"

SKIPFILE="${SKIPFILE:-/cc/skipfile.txt}"
ENABLE_PROFILE="${ENABLE_PROFILE:-}"
DISABLE_CHECKERS="${DISABLE_CHECKERS:-}"
# Extra checkers that recover Coverity-class defects the default profile misses:
#   performance-unnecessary-copy-initialization  -> "use of auto that causes a copy"
#   unix.BlockInCriticalSection                  -> "waiting while holding a lock"
#   (checker graduated from alpha in clang-20; alpha.unix.BlockInCriticalSection gone)
ENABLE_CHECKERS="${ENABLE_CHECKERS:-performance-unnecessary-copy-initialization unix.BlockInCriticalSection}"

# CTU finds interprocedural bugs missed by per-TU analysis.
# Requires clang-extdef-mapping in PATH (provided by clang-tools-20).
# Set ENABLE_CTU=0 to disable (adds ~2-3x analysis time).
ENABLE_CTU="${ENABLE_CTU:-1}"

JOBS="${JOBS:-$(nproc)}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
print_step() { echo -e "${YELLOW}\n==> $1${NC}"; }
print_ok()   { echo -e "${GREEN}  [OK]   $1${NC}"; }
print_warn() { echo -e "${YELLOW}  [WARN] $1${NC}"; }
print_err()  { echo -e "${RED}  [FAIL] $1${NC}"; }
die()        { print_err "$1"; exit 1; }

check_prereqs() {
    print_step "Checking analyzer prerequisites"
    for tool in git make cmake clang clang-tidy cppcheck CodeChecker curl; do
        command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
    done
    mkdir -p "$WORKSPACE" "$RESULTS_DIR"
    print_ok "toolchain present; CodeChecker $(CodeChecker version 2>/dev/null | head -1)"
}

wait_for_server() {
    print_step "Waiting for CodeChecker server at ${SERVER_URL%/Default}"
    local base="${SERVER_URL%/Default}"
    for _ in $(seq 1 30); do
        curl -fsS "$base/" >/dev/null 2>&1 && { print_ok "server reachable"; return 0; }
        sleep 5
    done
    print_warn "server not reachable — CLI diff still works; store will be skipped"
    return 1
}

ensure_clone() {
    print_step "Ensuring wazuh clone at $WAZUH_DIR"
    if [ -d "$WAZUH_DIR/.git" ]; then
        print_ok "clone present — reusing"
    else
        git clone "$REPO_URL" "$WAZUH_DIR" || die "git clone failed"
        print_ok "cloned $REPO_URL"
    fi
    git -C "$WAZUH_DIR" fetch --tags --force || die "git fetch failed"
}

build_analyze_flags() {
    ANALYZE_FLAGS=()
    if [ -n "$SKIPFILE" ] && [ -f "$SKIPFILE" ]; then
        ANALYZE_FLAGS+=( --skip "$SKIPFILE" )
        print_ok "using skip file: $SKIPFILE"
    fi
    [ -n "$ENABLE_PROFILE" ] && ANALYZE_FLAGS+=( --enable "$ENABLE_PROFILE" )
    local chk
    for chk in $ENABLE_CHECKERS; do ANALYZE_FLAGS+=( --enable "$chk" ); done
    [ -n "$ENABLE_CHECKERS" ] && print_ok "extra checkers: $ENABLE_CHECKERS"
    for chk in $DISABLE_CHECKERS; do ANALYZE_FLAGS+=( --disable "$chk" ); done
    if [ "${ENABLE_CTU:-1}" = "1" ]; then
        if command -v clang-extdef-mapping >/dev/null 2>&1; then
            ANALYZE_FLAGS+=( --ctu )
            print_ok "CTU enabled"
        else
            print_warn "clang-extdef-mapping not found — CTU disabled"
        fi
    fi
}

run_scan() {
    local ref="$1" slug="$2"
    local cc_json="$WAZUH_DIR/compile_commands_${slug}.json"
    local reports="$WAZUH_DIR/reports_${slug}"

    print_step "[$slug] Checkout $ref"
    if ! git -C "$WAZUH_DIR" rev-parse --verify --quiet "${ref}^{commit}" >/dev/null; then
        git -C "$WAZUH_DIR" fetch --force origin "$ref" 2>/dev/null \
            || git -C "$WAZUH_DIR" fetch --force --tags origin 2>/dev/null || true
    fi
    git -C "$WAZUH_DIR" checkout --force "$ref"              || die "[$slug] checkout failed"
    git -C "$WAZUH_DIR" submodule update --init --recursive  || die "[$slug] submodule update failed"

    print_step "[$slug] Clean stale build artefacts"
    git -C "$WAZUH_DIR" clean -xdf -e 'reports_*' -e 'compile_commands_*.json' || true
    find "$WAZUH_DIR" -type d -name build -prune -exec rm -rf {} + 2>/dev/null || true

    print_step "[$slug] make deps TARGET=$TARGET"
    ( cd "$WAZUH_DIR/src" && make deps TARGET="$TARGET" -j"$JOBS" ) || die "[$slug] make deps failed"

    print_step "[$slug] CodeChecker log (ld-logger build capture)"
    ( cd "$WAZUH_DIR/src" && \
      CodeChecker log -b "make TARGET=$TARGET DEBUG=1 -j$JOBS" -o "$cc_json" ) \
        || die "[$slug] CodeChecker log failed"
    [ -s "$cc_json" ] || die "[$slug] empty compile_commands"
    print_ok "[$slug] captured $(grep -c '"file"' "$cc_json" 2>/dev/null || echo '?') TUs"

    print_step "[$slug] CodeChecker analyze"
    build_analyze_flags
    rm -rf "$reports"
    CodeChecker analyze "$cc_json" -o "$reports" -j"$JOBS" "${ANALYZE_FLAGS[@]}" \
        || print_warn "[$slug] analyze non-zero (findings present is normal)"
    [ -d "$reports" ] || die "[$slug] no reports dir produced"
    print_ok "[$slug] reports in $reports"
}

run_diff() {
    local b="$WAZUH_DIR/reports_base" n="$WAZUH_DIR/reports_target"
    print_step "CLI diff (base=$BASE_REF  target=$TARGET_REF)"
    [ -d "$b" ] || die "missing base reports: $b"
    [ -d "$n" ] || die "missing target reports: $n"

    CodeChecker cmd diff -b "$b" -n "$n" --new        > "$RESULTS_DIR/diff_new.txt"        2>&1 || true
    CodeChecker cmd diff -b "$b" -n "$n" --resolved   > "$RESULTS_DIR/diff_resolved.txt"   2>&1 || true
    CodeChecker cmd diff -b "$b" -n "$n" --unresolved > "$RESULTS_DIR/diff_unresolved.txt" 2>&1 || true
    print_ok "wrote diff_new.txt / diff_resolved.txt / diff_unresolved.txt"

    CodeChecker cmd diff -b "$b" -n "$n" --new -o json -e "$RESULTS_DIR/diff_new.json" >/dev/null 2>&1 \
        && print_ok "exported diff_new.json" || true

    CodeChecker cmd diff -b "$b" -n "$n" --new -o html -e "$RESULTS_DIR/diff_new_html" >/dev/null 2>&1 \
        && print_ok "exported diff HTML -> results/diff_new_html/" || true
}

store_run() {
    local reports="$1" name="$2" cc_json="${3:-}"
    local base="${SERVER_URL%/Default}"
    curl -fsS "$base/" >/dev/null 2>&1 || { print_warn "server unreachable — skipping store of $name"; return 0; }
    print_step "Storing $name"
    local out rc
    out="$(CodeChecker store "$reports" --name "$name" --url "$SERVER_URL" 2>&1)"; rc=$?
    if [ $rc -eq 0 ]; then print_ok "stored: $name"; return 0; fi
    if echo "$out" | grep -q "source file contents changed" && [ -n "$cc_json" ] && [ -f "$cc_json" ]; then
        print_warn "[$name] source-check mismatch — re-analyzing and retrying store"
        build_analyze_flags
        rm -rf "$reports"
        CodeChecker analyze "$cc_json" -o "$reports" -j"$JOBS" "${ANALYZE_FLAGS[@]}" >/dev/null 2>&1 || true
        CodeChecker store "$reports" --name "$name" --url "$SERVER_URL" \
            && { print_ok "stored: $name (after re-analyze)"; return 0; } \
            || print_warn "store of $name still failed"
    else
        print_warn "store of $name failed"; echo "$out" | tail -3
    fi
}

mirror_results() {
    print_step "Mirroring artefacts to $RESULTS_DIR"
    cp -f "$WAZUH_DIR"/compile_commands_*.json "$RESULTS_DIR/" 2>/dev/null || true
    local slug
    for slug in base target; do
        local r="$WAZUH_DIR/reports_$slug"
        [ -d "$r" ] && CodeChecker parse "$r" > "$RESULTS_DIR/summary_${slug}.txt" 2>&1 || true
    done
    print_ok "results in $RESULTS_DIR"
    ls -1 "$RESULTS_DIR" | sed 's/^/    /'
}

main() {
    echo -e "${BLUE}CodeChecker differential scan${NC}"
    echo -e "${BLUE}  TARGET=$TARGET  jobs=$JOBS${NC}"
    echo -e "${BLUE}  BASE   $BASE_REF -> '$BASE_NAME'${NC}"
    echo -e "${BLUE}  TARGET $TARGET_REF -> '$TARGET_NAME'${NC}"

    [ -n "$BASE_REF" ]   || die "BASE_REF is required"
    [ -n "$TARGET_REF" ] || die "TARGET_REF is required"

    check_prereqs
    wait_for_server || true
    ensure_clone

    if [ -n "$SCAN_ONLY" ]; then
        run_scan "$BASE_REF" base
        store_run "$WAZUH_DIR/reports_base" "$BASE_NAME" "$WAZUH_DIR/compile_commands_base.json"
        CodeChecker parse "$WAZUH_DIR/reports_base" > "$RESULTS_DIR/summary_${BASE_NAME}.txt" 2>&1 || true
        print_ok "stored: $BASE_NAME  summary: $RESULTS_DIR/summary_${BASE_NAME}.txt"
        return 0
    fi

    run_scan "$BASE_REF"   base
    store_run "$WAZUH_DIR/reports_base"   "$BASE_NAME"   "$WAZUH_DIR/compile_commands_base.json"
    run_scan "$TARGET_REF" target
    store_run "$WAZUH_DIR/reports_target" "$TARGET_NAME" "$WAZUH_DIR/compile_commands_target.json"
    run_diff
    mirror_results

    print_step "Done"
    print_ok "CLI diffs:   $RESULTS_DIR/diff_{new,resolved,unresolved}.txt"
    print_ok "Visual diff: $HOST_UI_URL (compare '$BASE_NAME' vs '$TARGET_NAME')"
}

case "${1:-}" in
    --help|-h) grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -30; exit 0 ;;
    --clean)
        rm -rf "$WAZUH_DIR"/reports_* "$WAZUH_DIR"/compile_commands_*.json "$RESULTS_DIR"/* 2>/dev/null || true
        print_ok "cleared analyzer caches"; exit 0 ;;
    *) main "$@" ;;
esac
