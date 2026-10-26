#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# ab_indexer.sh — A/B of the manager's indexer sender: v1 (pre-v2) against v2 (RNF-3, plan 18 E11c).
#
# For each scenario it runs the two builds in ABBA order (ABBA BAAB ... : the order bias of a
# plain A,B,A,B cancels), N runs per side, after one warm-up run per side that is thrown away.
# I204: v2 passes when the median ratio v2/v1 of the verdict metrics is >= 0.95 (ab_report.py).
#
# A side is a snapshot of one build's bin/ lib/ and site-packages plus its internal-options,
# restored whole by `prepare_manager.sh --side` (save them first with --save-side). Labels:
# ab-<side>-<scenario>-<i> (the warm-up is <i> = w), results in results_<label>/.
#
# Scenarios (--list):
#   drain-engine        DRAIN  the indexer is paused for the whole run, resumed after it: docs/s and
#                              time to drain at the indexer (verdict). `engine_fleet_load`-style load.
#   drain-syscollector  DRAIN  the indexer is paused for AB_PAUSE_S while sessions are in flight:
#                              sessions/s (verdict) and the retained sessions' drain.
#   fixed-engine, fixed-syscollector, fixed-fim, fixed-vd
#                       FIXED  fixed-rate scenarios, a no-regression check of latency, CPU and RSS
#                              (reported, no verdict).
#
# Around every run: restore the side (only when it changes), provenance.txt (sha256 of
# bin/wazuh-manager-analysisd, bin/wazuh-manager-modulesd and lib/*.so; `wazuh-manager-conf
# validate`), the indexer cleaned by an ALLOW-LIST (wazuh-events*, wazuh-states-*, and the raw
# pattern in AB_RAW_PATTERN when set -- the same on both sides; NEVER .wazuh-threatintel-* nor
# .wazuh-cti-consumers: the VD scenario needs the feed), bench-* agents cleaned, the probe
# (indexer_ingest_probe.sh, _count per pattern per second) running, then ab_report.py collect.
#
# The whole window holds an exclusive flock on AB_MEASURE_LOCK (default results_ab/measure.lock
# next to this script; plan 18 uses /tmp/plan18-medida.lock), so nothing else builds or measures.
#
# --dry-run prints the whole plan -- runs, labels, restorations, cleanups -- and touches no
# manager, container, indexer or lock. Run a smoke first: one scenario, --n 2 (N is per side and
# even: ABBA needs pairs), as soon as the manager is free.
#
# Usage:
#   ./ab_indexer.sh [--scenario NAME]... [--kind drain|fixed|all] [--n 4] [--no-warmup]
#                   [--snapshots DIR] [--indexer-container wazuh-indexer] [--pause-seconds 30]
#                   [--quiet-seconds 60] [--drain-timeout 600] [--seed 4242]
#                   [--dry-run] [--list] [--report]
#   ./ab_indexer.sh --report            # ab_report.py over the results_ab-* directories
#
# The end of a run (wait_quiet): the indexer's summed _count has not grown for --quiet-seconds
# (default and FLOOR 60 s: a lower value is raised to 60, because after an `unpause` the sender
# legitimately idles for a node health probe (10 s), its backoff (up to 15 s) and the async flush
# (20 s) before it writes again), OR it reached the total the sender declares it sent (sender_summary.json:
# stateless events_sent in agent mode, session documents_sent in uds mode), OR --drain-timeout
# (the hard cap, 600 s: the run is then NOT a valid measurement). How it ended is recorded in
# drain.json ("drain_end": expected|quiet|timeout, "docs_final", "expected_docs").
#
# A campaign is one real invocation: it stamps a campaign id (UTC time + random) on every run it
# collects, and its final report reads ONLY the runs of that id, so results of an earlier, longer or
# aborted campaign cannot reach the medians. The exit status is the report's (0 pass, 1 fail, 2
# incomplete/incomparable), and never 0 when a scenario aborted (failed > 0 -> at least 2).
#
# Environment: AB_MEASURE_LOCK, AB_SOURCE_ONLY and AB_TEST_* (test hooks), AB_REEXEC_PRINT (test hook: print the re-exec command line and exit), AB_SNAPSHOTS, AB_RAW_PATTERN, AB_RUN_ARGS (extra run_benchmark.sh
#   flags, e.g. "--cluster cluster01"), INDEXER_URL / INDEXER_USER / INDEXER_PASSWORD /
#   INDEXER_CACERT (the indexer; see indexer_ingest_probe.sh), WAZUH_MANAGER_HOME.
#   The indexer is paused with `docker pause` (indexer_control.sh drives `service`, which does
#   not exist inside the e2e container).
# ---------------------------------------------------------------------------
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
WAZUH_HOME="${WAZUH_MANAGER_HOME:-/var/wazuh-manager}"
AB_MEASURE_LOCK="${AB_MEASURE_LOCK:-$SCRIPT_DIR/results_ab/measure.lock}"
SNAPSHOTS="${AB_SNAPSHOTS:-$SCRIPT_DIR/results_ab/snapshots}"
INDEXER_URL="${INDEXER_URL:-https://localhost:9200}"
INDEXER_USER="${INDEXER_USER:-admin}"
INDEXER_PASSWORD="${INDEXER_PASSWORD:-${INDEXER_PASS:-admin}}"
CONTAINER="wazuh-indexer"
N=4
WARMUP=true
KIND="all"
PAUSE_S=30
QUIET_S=60
QUIET_FLOOR_S="${AB_TEST_QUIET_FLOOR_S:-60}"   # AB_TEST_*: test hooks, never set in a real campaign
DRAIN_TIMEOUT_S=600
SEED=4242
DRY_RUN=false
DO_LIST=false
DO_REPORT=false
SELECTED=()
CAMPAIGN_ID=""   # stamped per real campaign, below the lock re-exec
ORIG_ARGS=("$@")   # the re-exec under the lock must replay them: the parse loop shifts them away

# name|kind|scenario|mode|resume|patterns|verdict metrics (comma separated)
#   patterns: what the probe counts AND what the end-of-run wait compares with the sender's total. The
#   syscollector drain counts only the inventory indices: VD's wazuh-states-vulnerabilities-* documents
#   would reach the total early and truncate docs_indexed.
#   resume: after-run = resume the indexer when the sender is done; timed = after PAUSE_S
SCENARIO_TABLE=(
    "drain-engine|drain|scenarios/ab_drain_engine.json|agent|after-run|wazuh-events*|docs_per_s_drain,drain_seconds"
    "drain-syscollector|drain|scenarios/ab_drain_syscollector_debian.json|uds|timed|wazuh-states-inventory-*|sessions_per_s"
    "fixed-engine|fixed|scenarios/engine_fleet_load.json|agent|none|wazuh-events*|"
    "fixed-syscollector|fixed|scenarios/syscollector_init_debian.json|uds|none|wazuh-states-*|"
    "fixed-fim|fixed|scenarios/fim_first_sync_ubuntu.json|uds|none|wazuh-states-*|"
    "fixed-vd|fixed|scenarios/vd_first_then_sync_debian.json|uds|none|wazuh-states-*|"
)

# What the cleaner may empty. Never a dot-index: the CTI feed and its consumer document live there.
CLEAN_ALLOW=("wazuh-events*" "wazuh-states-*")
[[ -n "${AB_RAW_PATTERN:-}" ]] && CLEAN_ALLOW+=("$AB_RAW_PATTERN")

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --scenario)            SELECTED+=("$2"); shift 2 ;;
        --kind)                KIND="$2"; shift 2 ;;
        --n)                   N="$2"; shift 2 ;;
        --no-warmup)           WARMUP=false; shift ;;
        --snapshots)           SNAPSHOTS="$2"; shift 2 ;;
        --indexer-container)   CONTAINER="$2"; shift 2 ;;
        --pause-seconds)       PAUSE_S="$2"; shift 2 ;;
        --quiet-seconds)       QUIET_S="$2"; shift 2 ;;
        --drain-timeout)       DRAIN_TIMEOUT_S="$2"; shift 2 ;;
        --seed)                SEED="$2"; shift 2 ;;
        --dry-run)             DRY_RUN=true; shift ;;
        --list)                DO_LIST=true; shift ;;
        --report)              DO_REPORT=true; shift ;;
        --locked)              shift ;;
        -h|--help)             usage; exit 0 ;;
        *) echo "ab_indexer: unknown option $1" >&2; usage >&2; exit 1 ;;
    esac
done

if ! [[ "$QUIET_S" =~ ^[0-9]+$ ]]; then
    echo "ab_indexer: --quiet-seconds is a number of seconds (got '$QUIET_S')" >&2; exit 1
fi
if (( QUIET_S < QUIET_FLOOR_S )); then
    echo "ab_indexer: --quiet-seconds $QUIET_S raised to the ${QUIET_FLOOR_S}s floor (the sender idles that long after a resume)" >&2
    QUIET_S=$QUIET_FLOOR_S
fi
[[ "$KIND" == "drain" || "$KIND" == "fixed" || "$KIND" == "all" ]] || {
    echo "ab_indexer: --kind is drain, fixed or all (got '$KIND')" >&2; exit 1; }
if ! [[ "$N" =~ ^[0-9]+$ ]] || (( N < 2 || N % 2 != 0 )); then
    echo "ab_indexer: --n is runs PER SIDE, even and >= 2 (ABBA needs pairs), got '$N'" >&2
    exit 1
fi

if $DO_LIST; then
    printf '%-20s %-6s %-6s %s\n' scenario kind mode file
    for row in "${SCENARIO_TABLE[@]}"; do
        IFS='|' read -r name kind file mode _ _ _ <<<"$row"
        printf '%-20s %-6s %-6s %s\n' "$name" "$kind" "$mode" "$file"
    done
    exit 0
fi
if $DO_REPORT; then
    exec "$PYTHON" "$SCRIPT_DIR/ab_report.py" report --root "$SCRIPT_DIR" \
        --json "$SCRIPT_DIR/results_ab/ab_report.json" --markdown "$SCRIPT_DIR/results_ab/ab_report.md"
fi

# The scenarios to run, in table order.
PLAN=()
for row in "${SCENARIO_TABLE[@]}"; do
    IFS='|' read -r name kind _ <<<"$row"
    [[ "$KIND" == "all" || "$KIND" == "$kind" ]] || continue
    if [[ ${#SELECTED[@]} -gt 0 ]]; then
        keep=false
        for s in "${SELECTED[@]}"; do [[ "$s" == "$name" ]] && keep=true; done
        $keep || continue
    fi
    PLAN+=("$row")
done
for s in "${SELECTED[@]:-}"; do
    [[ -z "$s" ]] && continue
    found=false
    for row in "${SCENARIO_TABLE[@]}"; do [[ "${row%%|*}" == "$s" ]] && found=true; done
    $found || { echo "ab_indexer: unknown scenario '$s' (see --list)" >&2; exit 1; }
done
[[ ${#PLAN[@]} -gt 0 ]] || { echo "ab_indexer: nothing selected (check --kind and --scenario)" >&2; exit 1; }

# The ABBA order of one scenario: ABBA BAAB ABBA ... for N runs per side, v1 first.
abba_sides() {
    local total=$((2 * N)) i block pos
    for ((i = 0; i < total; i++)); do
        block=$((i / 4)); pos=$((i % 4))
        if (( block % 2 == 0 )); then
            case $pos in 0) echo v1 ;; 1) echo v2 ;; 2) echo v2 ;; 3) echo v1 ;; esac
        else
            case $pos in 0) echo v2 ;; 1) echo v1 ;; 2) echo v1 ;; 3) echo v2 ;; esac
        fi
    done
}

# The sequence of runs of one scenario as "side|index" lines; the warm-ups come first, the
# side that opens the measured sequence last.
run_sequence() {
    local side count1=0 count2=0 first
    first="$(abba_sides | head -n1)"
    if $WARMUP; then
        if [[ "$first" == "v1" ]]; then echo "v2|w"; echo "v1|w"; else echo "v1|w"; echo "v2|w"; fi
    fi
    while read -r side; do
        if [[ "$side" == "v1" ]]; then count1=$((count1 + 1)); echo "v1|$count1"
        else count2=$((count2 + 1)); echo "v2|$count2"; fi
    done < <(abba_sides)
}

# The cleaning allow-list: refuse a pattern that could reach the CTI feed or everything.
check_clean_allow() {
    local p
    for p in "${CLEAN_ALLOW[@]}"; do
        case "$p" in
            .*|\**|_all|"") echo "ab_indexer: refusing to clean '$p' (dot-indices hold the CTI feed)" >&2; return 1 ;;
        esac
    done
}
check_clean_allow || exit 1

idx_curl() {  # the credentials go to curl on stdin (-K -), never in its argv
    local args=(-s -g --max-time 60 -K -) u="${INDEXER_USER}:${INDEXER_PASSWORD}"
    u="${u//\\/\\\\}"; u="${u//\"/\\\"}"
    if [[ -n "${INDEXER_CACERT:-}" ]]; then args+=(--cacert "$INDEXER_CACERT"); else args+=(-k); fi
    printf 'user = "%s"\n' "$u" | curl "${args[@]}" "$@"
}

clean_indexer() {  # empties each allow-listed pattern; the templates and mappings stay
    local p count
    for p in "${CLEAN_ALLOW[@]}"; do
        idx_curl -X POST "${INDEXER_URL}/${p}/_delete_by_query?conflicts=proceed&refresh=true&wait_for_completion=true" \
            -H 'Content-Type: application/json' -d '{"query":{"match_all":{}}}' >/dev/null
    done
    count="$(INDEXER_URL="$INDEXER_URL" INDEXER_USER="$INDEXER_USER" INDEXER_PASSWORD="$INDEXER_PASSWORD" \
        "$SCRIPT_DIR/indexer_ingest_probe.sh" --once --patterns "$(IFS=,; echo "${CLEAN_ALLOW[*]}")")" || return 1
    [[ "$count" == "0" ]] || { echo "ab_indexer: the indexer still holds $count documents after cleaning" >&2; return 1; }
}

write_provenance() {  # results_dir side
    local dir="$1" side="$2" f
    {
        echo "side: $side"
        echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        for f in "$WAZUH_HOME/bin/wazuh-manager-analysisd" "$WAZUH_HOME/bin/wazuh-manager-modulesd" "$WAZUH_HOME"/lib/*.so; do
            [[ -e "$f" ]] && sha256sum "$f"
        done
        if "$WAZUH_HOME/bin/wazuh-manager-conf" -f /etc/wazuh-manager/wazuh-manager.conf -H "$WAZUH_HOME" validate; then
            echo "conf validate: ok"
        else
            echo "conf validate: FAILED"
        fi
    } > "$dir/provenance.txt"
}

PAUSED=false
unpause_indexer() {
    if $PAUSED; then docker unpause "$CONTAINER" >/dev/null 2>&1 || true; PAUSED=false; fi
}

# A drain run without its pause measures nothing: a failed `docker pause` (wrong container name, no
# permission) aborts the run instead of letting it write a drain.json with a t_resume.
pause_indexer() {
    if docker pause "$CONTAINER" >/dev/null; then PAUSED=true; return 0; fi
    echo "ab_indexer: docker pause $CONTAINER failed: the drain run would not be a drain" >&2
    return 1
}
abort_run() {  # label
    kill "$PROBE_PID" 2>/dev/null; wait "$PROBE_PID" 2>/dev/null
    trap - EXIT
    echo "ab_indexer: $1 aborted: the run is NOT a valid measurement" >&2
}

DRAIN_END=""     # how wait_quiet ended: expected | quiet | timeout
DRAIN_FINAL=""   # the summed _count at that moment

# The total documents the sender says it sent, from its summary (0 when unknown).
expected_docs() {  # results_dir mode
    "$PYTHON" "$SCRIPT_DIR/ab_report.py" expected "$1" --mode "$2" 2>/dev/null || echo 0
}

wait_quiet() {  # patterns expected -> returns when the summed _count reached `expected` (> 0), or
                # has not grown for QUIET_S seconds; fails (the hard cap) after DRAIN_TIMEOUT_S
    local patterns="$1" expected="${2:-0}" prev=-1 cur stable=0 deadline=$((SECONDS + DRAIN_TIMEOUT_S))
    DRAIN_END=""; DRAIN_FINAL=""
    while (( SECONDS < deadline )); do
        cur="$(INDEXER_URL="$INDEXER_URL" INDEXER_USER="$INDEXER_USER" INDEXER_PASSWORD="$INDEXER_PASSWORD" \
            "$SCRIPT_DIR/indexer_ingest_probe.sh" --once --patterns "$patterns" 2>/dev/null)" || cur=-1
        if [[ "$cur" == "$prev" && "$cur" != "-1" ]]; then stable=$((stable + 1)); else stable=0; fi
        prev="$cur"
        if [[ "$cur" != "-1" ]] && (( expected > 0 && cur >= expected )); then
            DRAIN_END=expected; DRAIN_FINAL=$cur; return 0
        fi
        if (( stable >= QUIET_S )); then DRAIN_END=quiet; DRAIN_FINAL=$cur; return 0; fi
        sleep 1
    done
    DRAIN_END=timeout; DRAIN_FINAL=$prev
    echo "ab_indexer: the indexer was still growing after ${DRAIN_TIMEOUT_S}s (hard cap)" >&2
    return 1
}

PROBE_PID=""

run_one() {  # row side index position (e.g. 3/10)
    local row="$1" side="$2" i="$3" pos="$4" name kind file mode resume patterns verdicts label dir warm=""
    IFS='|' read -r name kind file mode resume patterns verdicts <<<"$row"
    label="ab-${side}-${name}-${i}"
    dir="$SCRIPT_DIR/results_${label}"
    [[ "$i" == "w" ]] && warm="(warm-up: discarded)"
    echo "  [$pos] $label  side=$side scenario=$name kind=$kind mode=$mode $warm"

    # Every run restores its side, even when the previous run was the same side: a restart gives
    # each run the same empty queues, counters and caches.
    echo "    restore side $side:"
    if $DRY_RUN; then
        "$SCRIPT_DIR/prepare_manager.sh" --side "$side" --side-only --dry-run --snapshots "$SNAPSHOTS" | sed 's/^/      /'
    else
        "$SCRIPT_DIR/prepare_manager.sh" --side "$side" --side-only --snapshots "$SNAPSHOTS" || return 1
    fi
    echo "    provenance: $dir/provenance.txt (sha256 of analysisd, modulesd, lib/*.so; conf validate)"
    echo "    clean the indexer by allow-list: ${CLEAN_ALLOW[*]} (never .wazuh-threatintel-* / .wazuh-cti-consumers)"
    [[ "$mode" == "agent" ]] && echo "    clean bench-* agents: cleanup_agents.sh"
    echo "    probe: indexer_ingest_probe.sh --patterns $patterns$([[ -n "${AB_RAW_PATTERN:-}" && "$mode" == agent ]] && echo ",$AB_RAW_PATTERN") -> $dir/probe.csv"
    case "$resume" in
        after-run) echo "    docker pause $CONTAINER; run the sender; docker unpause $CONTAINER; wait until the count reaches the sender's total or is quiet ${QUIET_S}s (cap ${DRAIN_TIMEOUT_S}s)" ;;
        timed)     echo "    docker pause $CONTAINER; run the sender; docker unpause after ${PAUSE_S}s; wait until the count reaches the sender's total or is quiet ${QUIET_S}s (cap ${DRAIN_TIMEOUT_S}s)" ;;
        *)         echo "    run the sender; wait until the count reaches the sender's total or is quiet ${QUIET_S}s (cap ${DRAIN_TIMEOUT_S}s)" ;;
    esac
    echo "    run_benchmark.sh --scenario $file --label $label --mode $mode --seed $SEED ${AB_RUN_ARGS:-}"
    echo "    ab_report.py collect $dir --side $side --scenario $name --index $i --kind $kind${verdicts:+ verdict: $verdicts}"
    $DRY_RUN && return 0

    local probe_patterns="$patterns" rc=0 t_pause="" t_resume="" bench_pid args=()
    [[ -n "${AB_RAW_PATTERN:-}" && "$mode" == "agent" ]] && probe_patterns="$patterns,$AB_RAW_PATTERN"
    mkdir -p "$dir"
    rm -f "$dir/ab_metrics.json" "$dir/drain.json"   # a run that aborts must not leave an older run's numbers
    write_provenance "$dir" "$side"
    clean_indexer || return 1
    [[ "$mode" == "agent" ]] && { "$SCRIPT_DIR/cleanup_agents.sh" >/dev/null 2>&1 || true; }

    INDEXER_URL="$INDEXER_URL" INDEXER_USER="$INDEXER_USER" INDEXER_PASSWORD="$INDEXER_PASSWORD" \
        "$SCRIPT_DIR/indexer_ingest_probe.sh" --out "$dir/probe.csv" --patterns "$probe_patterns" &
    PROBE_PID=$!
    trap 'unpause_indexer; kill "$PROBE_PID" 2>/dev/null' EXIT

    args=(--scenario "$SCRIPT_DIR/$file" --label "$label" --mode "$mode" --seed "$SEED")
    [[ "$mode" == "agent" ]] && args+=(--enroll-settle 240s)
    # shellcheck disable=SC2206
    args+=(${AB_RUN_ARGS:-})
    case "$resume" in
        after-run)
            pause_indexer || { abort_run "$label"; return 1; }
            t_pause="$(date +%s.%N)"
            "$SCRIPT_DIR/run_benchmark.sh" "${args[@]}" || rc=$?
            unpause_indexer; t_resume="$(date +%s.%N)" ;;
        timed)
            pause_indexer || { abort_run "$label"; return 1; }
            t_pause="$(date +%s.%N)"
            "$SCRIPT_DIR/run_benchmark.sh" "${args[@]}" & bench_pid=$!
            sleep "$PAUSE_S"
            unpause_indexer; t_resume="$(date +%s.%N)"
            wait "$bench_pid" || rc=$? ;;
        *)
            "$SCRIPT_DIR/run_benchmark.sh" "${args[@]}" || rc=$? ;;
    esac
    local expected
    expected="$(expected_docs "$dir" "$mode")"
    # The agent-mode probe also counts AB_RAW_PATTERN (one raw copy per event): the target doubles, so a
    # sum of events + raw copies cannot reach it before the drain is over.
    [[ -n "${AB_RAW_PATTERN:-}" && "$mode" == "agent" ]] && expected=$((expected * 2))
    wait_quiet "$probe_patterns" "$expected" || rc=1
    kill "$PROBE_PID" 2>/dev/null; wait "$PROBE_PID" 2>/dev/null
    trap - EXIT
    [[ -n "$t_resume" ]] && printf '{"t_pause": %s, "t_resume": %s, "drain_end": "%s", "docs_final": %s, "expected_docs": %s}\n' \
        "$t_pause" "$t_resume" "$DRAIN_END" "${DRAIN_FINAL:--1}" "$expected" > "$dir/drain.json"
    # exit 3 = the sender's measurement is valid but its `expected` block failed: kept, flagged
    if (( rc != 0 && rc != 3 )); then
        echo "ab_indexer: $label ended with exit $rc: the run is NOT a valid measurement" >&2
        return 1
    fi
    local collect=("$PYTHON" "$SCRIPT_DIR/ab_report.py" collect "$dir" --side "$side" --scenario "$name"
                   --index "$i" --kind "$kind" --campaign "$CAMPAIGN_ID")
    [[ "$i" == "w" ]] && collect+=(--warmup)
    local m
    for m in ${verdicts//,/ }; do collect+=(--verdict-metric "$m"); done
    "${collect[@]}" >/dev/null
}

# Test hook: `AB_SOURCE_ONLY=1 source ab_indexer.sh <args>` defines the functions and stops, so a test
# can drive wait_quiet or run_one on its own.
# shellcheck disable=SC2317  # `exit` is reached when executed instead of sourced
if [[ -n "${AB_SOURCE_ONLY:-}" ]]; then return 0 2>/dev/null || exit 0; fi

# The measurement window is exclusive: re-exec under the lock (a dry run takes none).
if ! $DRY_RUN && [[ -z "${AB_LOCKED:-}" ]]; then
    mkdir -p "$(dirname "$AB_MEASURE_LOCK")"
    if [[ -n "${AB_REEXEC_PRINT:-}" ]]; then   # test hook: show the command, run nothing
        printf 'REEXEC flock %s bash %s' "$AB_MEASURE_LOCK" "$0"
        printf ' [%s]' "${ORIG_ARGS[@]}"; printf ' [--locked]\n'
        exit 0
    fi
    AB_LOCKED=1 exec flock "$AB_MEASURE_LOCK" "${BASH:-bash}" "$0" "${ORIG_ARGS[@]}" --locked
fi

# One id per real campaign: UTC time + random. ab_report.py report reads only the runs stamped with it.
CAMPAIGN_ID="${AB_TEST_CAMPAIGN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-${RANDOM}${RANDOM}}"
total_runs=0
$DRY_RUN && echo "[dry-run] nothing below touches the manager, the indexer, a container or the lock"
echo "ab_indexer: ${#PLAN[@]} scenario(s), N=$N per side, warm-up $($WARMUP && echo yes || echo no), lock $AB_MEASURE_LOCK"
echo "            snapshots $SNAPSHOTS, indexer container $CONTAINER, verdict: median v2/v1 >= 0.95 (I204)"
failed=0
for row in "${PLAN[@]}"; do
    name="${row%%|*}"
    echo ""
    echo "== $name"
    pos=0
    mapfile -t seq < <(run_sequence)
    for entry in "${seq[@]}"; do
        pos=$((pos + 1)); total_runs=$((total_runs + 1))
        run_one "$row" "${entry%%|*}" "${entry##*|}" "$pos/${#seq[@]}" || { failed=$((failed + 1)); break; }
    done
done
echo ""
echo "ab_indexer: $total_runs run(s) $($DRY_RUN && echo planned || echo executed), $failed scenario(s) aborted"
if ! $DRY_RUN; then
    "$PYTHON" "$SCRIPT_DIR/ab_report.py" report --root "$SCRIPT_DIR" --campaign "$CAMPAIGN_ID" \
        --json "$SCRIPT_DIR/results_ab/ab_report.json" --markdown "$SCRIPT_DIR/results_ab/ab_report.md"
    rc=$?
    if (( failed > 0 && rc == 0 )); then
        echo "ab_indexer: $failed scenario(s) aborted: the campaign is incomplete (exit 2)" >&2
        rc=2
    fi
    exit $rc
fi
exit 0
