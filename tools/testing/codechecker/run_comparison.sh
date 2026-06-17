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

# Flawfinder detects C/C++ security patterns (CWE-362 TOCTOU, CWE-119 buffer overflows, etc.)
# that clangsa/cppcheck/clang-tidy miss.  Results are converted to CodeChecker format via
# `report-converter -t flawfinder` and stored as a separate run on the dashboard.
# Enabled by default; set RUN_FLAWFINDER=0 to skip.
RUN_FLAWFINDER="${RUN_FLAWFINDER:-1}"

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
    # Skip fetch when the repo has no remotes (e.g. the selftest git repo).
    if git -C "$WAZUH_DIR" remote | grep -q .; then
        git -C "$WAZUH_DIR" fetch --tags --force || die "git fetch failed"
    fi
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
    if ! git -C "$WAZUH_DIR" rev-parse --verify --quiet "${ref}^{commit}" >/dev/null 2>&1; then
        # Fetch the ref by name — for branches this writes the tip to FETCH_HEAD.
        # Fall back to --tags so tag refs are covered even if the name fetch fails.
        git -C "$WAZUH_DIR" fetch --force origin "$ref" 2>/dev/null || true
        git -C "$WAZUH_DIR" fetch --force --tags origin 2>/dev/null || true
    fi
    # 1. Direct checkout — works for tags, SHAs, and local branches.
    # 2. FETCH_HEAD checkout — works for remote branches just fetched above;
    #    -B creates (or resets) a local branch pointing at the fetched commit.
    git -C "$WAZUH_DIR" checkout --force "$ref" 2>/dev/null \
        || git -C "$WAZUH_DIR" checkout --force -B "$ref" FETCH_HEAD \
        || die "[$slug] checkout of '$ref' failed — not a reachable tag, branch, or SHA"
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

    # If a defect_samples directory is present in the checked-out tree
    # (test/codechecker-defect-samples branch), capture and merge its
    # compilation so those defects appear in the analysis results.
    local samples_dir="$WAZUH_DIR/tools/testing/codechecker/defect_samples"
    if [ -d "$samples_dir" ]; then
        print_step "[$slug] Capturing defect_samples (test validation)"
        local samples_json="$WAZUH_DIR/compile_commands_samples_${slug}.json"
        ( cd "$samples_dir" && \
          CodeChecker log -b "make clean all" -o "$samples_json" ) 2>/dev/null || true
        if [ -s "$samples_json" ]; then
            python3 - "$cc_json" "$samples_json" <<'PYEOF'
import json, sys
a = json.load(open(sys.argv[1]))
b = json.load(open(sys.argv[2]))
json.dump(a + b, open(sys.argv[1], 'w'))
PYEOF
            print_ok "[$slug] merged defect_samples ($(grep -c '"file"' "$samples_json" 2>/dev/null || echo '?') extra TUs)"
        else
            print_warn "[$slug] defect_samples build produced no compile_commands — skipping merge"
        fi
    fi

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

    # CodeChecker cmd diff exits 2 when findings exist — use || true so the export always runs.
    CodeChecker cmd diff -b "$b" -n "$n" --new -o json -e "$RESULTS_DIR/diff_new.json" >/dev/null 2>&1 || true
    [ -f "$RESULTS_DIR/diff_new.json/reports.json" ] && print_ok "exported diff_new.json" || true

    CodeChecker cmd diff -b "$b" -n "$n" --resolved -o json -e "$RESULTS_DIR/diff_resolved.json" >/dev/null 2>&1 || true
    [ -f "$RESULTS_DIR/diff_resolved.json/reports.json" ] && print_ok "exported diff_resolved.json" || true

    CodeChecker cmd diff -b "$b" -n "$n" --new -o html -e "$RESULTS_DIR/diff_new_html" >/dev/null 2>&1 || true
    [ -d "$RESULTS_DIR/diff_new_html" ] && print_ok "exported diff HTML -> results/diff_new_html/" || true

    # Append Flawfinder differential findings to the same output files when both
    # base and target were scanned.  The JSON exports merge into the same dirs so
    # generate_report.sh sees a single consolidated reports.json per direction.
    local fb="$WORKSPACE/reports_flawfinder_base" fn="$WORKSPACE/reports_flawfinder_target"
    if [ -d "$fb" ] && [ -d "$fn" ]; then
        print_step "Flawfinder diff (base=$BASE_REF  target=$TARGET_REF)"
        CodeChecker cmd diff -b "$fb" -n "$fn" --new      >> "$RESULTS_DIR/diff_new.txt"        2>&1 || true
        CodeChecker cmd diff -b "$fb" -n "$fn" --resolved >> "$RESULTS_DIR/diff_resolved.txt"   2>&1 || true
        CodeChecker cmd diff -b "$fb" -n "$fn" --unresolved >> "$RESULTS_DIR/diff_unresolved.txt" 2>&1 || true
        print_ok "appended flawfinder diff to diff_{new,resolved,unresolved}.txt"

        # Merge flawfinder JSON findings into the same diff_new.json / diff_resolved.json
        # directories so generate_report.sh picks them up alongside clangsa/cppcheck results.
        # NOTE: CodeChecker cmd diff exits 2 (not 0) when findings are present, so the JSON
        # export and the python merge must be separate steps — chaining them with && causes
        # the merge to be silently skipped whenever flawfinder finds anything.
        local fw_new_dir="$RESULTS_DIR/diff_new.json"
        local fw_res_dir="$RESULTS_DIR/diff_resolved.json"

        CodeChecker cmd diff -b "$fb" -n "$fn" --new -o json -e "${fw_new_dir}_fw" >/dev/null 2>&1 || true
        if [ -f "${fw_new_dir}_fw/reports.json" ]; then
            python3 /cc/merge_reports_json.py "${fw_new_dir}_fw/reports.json" "$fw_new_dir/reports.json" \
                && print_ok "merged flawfinder new findings into diff_new.json" \
                || print_warn "flawfinder JSON merge (new) failed — text diff still updated"
        fi
        rm -rf "${fw_new_dir}_fw"

        CodeChecker cmd diff -b "$fb" -n "$fn" --resolved -o json -e "${fw_res_dir}_fw" >/dev/null 2>&1 || true
        if [ -f "${fw_res_dir}_fw/reports.json" ]; then
            python3 /cc/merge_reports_json.py "${fw_res_dir}_fw/reports.json" "$fw_res_dir/reports.json" \
                && print_ok "merged flawfinder resolved findings into diff_resolved.json" \
                || print_warn "flawfinder JSON merge (resolved) failed — text diff still updated"
        fi
        rm -rf "${fw_res_dir}_fw"
    fi
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

# run_flawfinder <slug>
#   slug: "base" or "target" — determines which run name and CSV output file to use.
#   Must be called while the wazuh tree is already checked out at the corresponding ref
#   (i.e. immediately after run_scan for that slug).
run_flawfinder() {
    local slug="${1:-target}"

    if [ "${RUN_FLAWFINDER:-1}" != "1" ]; then
        print_step "Flawfinder skipped (RUN_FLAWFINDER=0)"
        return 0
    fi
    if ! command -v flawfinder >/dev/null 2>&1; then
        print_warn "flawfinder not in PATH — skipping (install: pip install flawfinder)"
        return 0
    fi

    # flawfinder_to_plist.py is baked into the image at /cc/
    local converter="${SCRIPTS_DIR:-/cc}/flawfinder_to_plist.py"
    if [ ! -f "$converter" ]; then
        print_warn "flawfinder_to_plist.py not found at $converter — skipping"
        return 0
    fi

    local ref_label
    case "$slug" in
        base)   ref_label="$BASE_REF";   run_name="${BASE_NAME}-flawfinder"   ;;
        target) ref_label="$TARGET_REF"; run_name="${TARGET_NAME}-flawfinder" ;;
        *) die "run_flawfinder: unknown slug '$slug' (expected base|target)" ;;
    esac

    print_step "Flawfinder scan ($slug=$ref_label)"

    local fw_csv="$WORKSPACE/flawfinder_${slug}.csv"
    local fw_reports="$WORKSPACE/reports_flawfinder_${slug}"

    # --csv produces structured output; flawfinder_to_plist.py converts it to
    # CodeChecker plist format (report-converter -t flawfinder does not exist in 6.27.3).
    flawfinder --minlevel=1 --csv --columns "$WAZUH_DIR/src" > "$fw_csv" 2>/dev/null || true
    if [ ! -s "$fw_csv" ]; then
        print_warn "flawfinder produced no output for $slug — skipping"
        return 0
    fi
    print_ok "flawfinder CSV ($slug): $(wc -l < "$fw_csv") lines"

    rm -rf "$fw_reports"
    if python3 "$converter" "$fw_csv" "$fw_reports" 2>&1; then
        cp -f "$fw_csv" "$RESULTS_DIR/flawfinder_${slug}.csv" 2>/dev/null || true
        print_ok "plist files in $fw_reports"
        store_run "$fw_reports" "$run_name"
    else
        print_warn "flawfinder_to_plist.py failed ($slug) — CSV saved to $RESULTS_DIR/flawfinder_${slug}.csv"
        cp -f "$fw_csv" "$RESULTS_DIR/flawfinder_${slug}.csv" 2>/dev/null || true
    fi
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
    run_flawfinder base

    run_scan "$TARGET_REF" target
    store_run "$WAZUH_DIR/reports_target" "$TARGET_NAME" "$WAZUH_DIR/compile_commands_target.json"
    run_flawfinder target

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
