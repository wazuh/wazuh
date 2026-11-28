#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# ab_indexer.sh — A/B of the manager's indexer sender: v1 (pre-v2) against v2.
#
# For each scenario it runs the two builds in ABBA order (ABBA BAAB ... : the order bias of a
# plain A,B,A,B cancels), N runs per side, after one warm-up run per side that is thrown away.
# v2 passes when the median ratio v2/v1 of the verdict metrics is >= 0.95 (ab_report.py).
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
# next to this script; set AB_MEASURE_LOCK to share one lock across worktrees), so nothing else builds or measures.
# The lock is held by the `flock -o` process only: its descriptor is closed before this script runs
# again under it, so the manager daemons a run restarts never inherit it (they outlive the campaign).
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
# (20 s) before it writes again), OR --drain-timeout (the hard cap, 600 s: the run is then NOT a
# valid measurement). There is no "expected total" end: remoted answers part of the burst 503
# (not retried) and the ruleset may leave part of the sample unindexed, so no total is known ahead.
# drain.json records how it ended ("drain_end": quiet|timeout, "docs_final"), what the manager
# ACCEPTED from the sender ("events_sent", "events_accepted", "events_rejected_503": ab_report.py
# accepted) and the engine's indexer.events.dropped read from its API at the end of the run
# ("engine_events_dropped", null when the API did not answer). ab_report.py judges the drain only
# when both sides indexed the same FRACTION of the accepted events (+-1 %) and dropped nothing.
#
# A campaign is one real invocation: it stamps a campaign id (UTC time + random) on every run it
# collects, and its final report reads ONLY the runs of that id, so results of an earlier, longer or
# aborted campaign cannot reach the medians. The exit status is the report's (0 pass, 1 fail, 2
# incomplete/incomparable), and never 0 when a scenario aborted (failed > 0 -> at least 2).
#
# Environment: AB_MEASURE_LOCK, AB_SOURCE_ONLY and AB_TEST_* (test hooks), AB_REEXEC_PRINT (test hook: print the re-exec command line and exit), AB_SNAPSHOTS, AB_RAW_PATTERN, AB_RUN_ARGS (extra run_benchmark.sh
#   flags, e.g. "--cluster cluster01"), INDEXER_URL (without it the address is the first
#   <indexer><hosts><host> of the manager's config, else https://127.0.0.1:9200), the indexer's
#   credentials and CA (indexer_credentials.sh: INDEXER_USER + INDEXER_PASSWORD, else the
#   WAZUH_INDEXER_ADMIN_PASSWORD of INDEXER_CREDENTIALS_FILE / the e2e .credentials.env /
#   /etc/wazuh-indexer/export/credentials.env, parsed, never sourced -- NO default: a real campaign
#   without one exits 1 before taking the lock; INDEXER_CACERT, else the manager config's indexer
#   CA, else /etc/wazuh-manager/certs/indexer-ca.pem; `-k` only with INDEXER_INSECURE=1),
#   WAZUH_MANAGER_HOME, AB_ENGINE_API_SOCKET (default $WAZUH_MANAGER_HOME/queue/sockets/engine-api-http.sock),
#   and the cleaner's WAZUH_API_USER / WAZUH_API_PASS (see cleanup_agents.sh: without them it reads
#   /etc/wazuh-manager/export/credentials.env as root; a run whose agent cleanup fails is aborted).
#   The indexer is paused with `docker pause` (indexer_control.sh drives `service`, which does
#   not exist inside the e2e container).
# ---------------------------------------------------------------------------
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
WAZUH_HOME="${WAZUH_MANAGER_HOME:-/var/wazuh-manager}"
AB_MEASURE_LOCK="${AB_MEASURE_LOCK:-$SCRIPT_DIR/results_ab/measure.lock}"
SNAPSHOTS="${AB_SNAPSHOTS:-$SCRIPT_DIR/results_ab/snapshots}"
INDEXER_URL="${INDEXER_URL:-$(WAZUH_MANAGER_CONF="${WAZUH_MANAGER_CONF:-}" "$SCRIPT_DIR/indexer_ingest_probe.sh" --print-url 2>/dev/null)}"
INDEXER_URL="${INDEXER_URL:-https://127.0.0.1:9200}"
ENGINE_API_SOCKET="${AB_ENGINE_API_SOCKET:-$WAZUH_HOME/queue/sockets/engine-api-http.sock}"
# shellcheck source=indexer_credentials.sh
source "$SCRIPT_DIR/indexer_credentials.sh"
INDEXER_TLS_ARGS=()   # set, with INDEXER_USER / INDEXER_PASSWORD, below the AB_SOURCE_ONLY hook
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
    indexer_curl_user_line | curl -s -g --max-time 60 -K - "${INDEXER_TLS_ARGS[@]}" "$@"
}

# indexer_ingest_probe.sh with this campaign's address, credentials and CA (resolved once, below).
# `probe ... &` leaves a subshell's PID in $!: stop it with kill_probe, which also stops the sampler.
probe() {
    INDEXER_URL="$INDEXER_URL" INDEXER_USER="${INDEXER_USER:-}" INDEXER_PASSWORD="${INDEXER_PASSWORD:-}" \
        INDEXER_CACERT="${INDEXER_CACERT:-}" INDEXER_INSECURE="${INDEXER_INSECURE:-}" \
        "$SCRIPT_DIR/indexer_ingest_probe.sh" "$@"
}

clean_indexer() {  # empties each allow-listed pattern; the templates and mappings stay
    local p count
    for p in "${CLEAN_ALLOW[@]}"; do
        idx_curl -X POST "${INDEXER_URL}/${p}/_delete_by_query?conflicts=proceed&refresh=true&wait_for_completion=true" \
            -H 'Content-Type: application/json' -d '{"query":{"match_all":{}}}' >/dev/null
    done
    count="$(probe --once --patterns "$(IFS=,; echo "${CLEAN_ALLOW[*]}")")" || return 1
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
kill_probe() {
    [[ -n "$PROBE_PID" ]] || return 0
    pkill -TERM -P "$PROBE_PID" 2>/dev/null; kill "$PROBE_PID" 2>/dev/null; wait "$PROBE_PID" 2>/dev/null
}
abort_run() {  # label
    kill_probe
    trap - EXIT
    echo "ab_indexer: $1 aborted: the run is NOT a valid measurement" >&2
}

DRAIN_END=""     # how wait_quiet ended: quiet | timeout
DRAIN_FINAL=""   # the summed _count at that moment

# What the manager accepted from the sender, as the JSON of `ab_report.py accepted --json` ({} unknown).
accepted_json() {  # results_dir mode
    "$PYTHON" "$SCRIPT_DIR/ab_report.py" accepted "$1" --mode "$2" --json 2>/dev/null || echo '{}'
}

# The engine's indexer.events.dropped since its last restart (every run restarts the manager), or
# `null` when the engine API does not answer.
engine_dropped() {
    local v
    v="$(curl -s --max-time 5 --unix-socket "$ENGINE_API_SOCKET" -X POST http://localhost/metrics/dump \
        -H 'Content-Type: application/json' -d '{}' 2>/dev/null \
        | "$PYTHON" "$SCRIPT_DIR/ab_report.py" engine-metric indexer.events.dropped 2>/dev/null)" || v=""
    [[ "$v" =~ ^[0-9]+$ ]] && echo "$v" || echo null
}

wait_quiet() {  # patterns -> returns when the summed _count has not grown for QUIET_S seconds;
                # fails (the hard cap) after DRAIN_TIMEOUT_S
    local patterns="$1" prev=-1 cur stable=0 deadline=$((SECONDS + DRAIN_TIMEOUT_S))
    DRAIN_END=""; DRAIN_FINAL=""
    while (( SECONDS < deadline )); do
        cur="$(probe --once --patterns "$patterns" 2>/dev/null)" || cur=-1
        if [[ "$cur" == "$prev" && "$cur" != "-1" ]]; then stable=$((stable + 1)); else stable=0; fi
        prev="$cur"
        if (( stable >= QUIET_S )); then DRAIN_END=quiet; DRAIN_FINAL=$cur; return 0; fi
        sleep 1
    done
    DRAIN_END=timeout; DRAIN_FINAL=$prev
    echo "ab_indexer: the indexer was still growing after ${DRAIN_TIMEOUT_S}s (hard cap)" >&2
    return 1
}

PROBE_PID=""

# After a restore the run must start from a manager that is up and sees the indexer:
# `wazuh-manager-control restart` returns before modulesd binds the inventory-sync socket, and v2's
# inventory_sync can start "not reachable" and re-probe only 60 s later (its 503s reject the agent
# deletions of the cleanup and, under a paused indexer, the socket appears ~8 s late). Wait, from the
# log line LOG_MARK on, for inventory_sync's "The indexer is reachable" and for both UDS sockets.
# AB_TEST_READY_TIMEOUT_S / AB_TEST_READY_SETTLE_S shorten it; AB_TEST_SKIP_READY=1 skips it (test
# hooks: a simulated campaign has no manager log to wait on).
READY_TIMEOUT_S="${AB_TEST_READY_TIMEOUT_S:-150}"
READY_SETTLE_S="${AB_TEST_READY_SETTLE_S:-3}"
READY_LINE='inventory-sync-server: INFO: The indexer is reachable'
manager_log_mark() {  # the line number the next log line will have
    echo $(( $(wc -l < "$WAZUH_HOME/logs/wazuh-manager.log" 2>/dev/null || echo 0) + 1 ))
}
wait_manager_ready() {  # log_mark
    local mark="$1" log="$WAZUH_HOME/logs/wazuh-manager.log" deadline=$((SECONDS + READY_TIMEOUT_S)) t0=$SECONDS
    [[ -n "${AB_TEST_SKIP_READY:-}" ]] && return 0
    until tail -n "+$mark" "$log" 2>/dev/null | grep -qF "$READY_LINE" \
          && [[ -S "$WAZUH_HOME/queue/sockets/inventory-sync-http.sock" && -S "$ENGINE_API_SOCKET" ]]; do
        (( SECONDS >= deadline )) && { echo "    ready: timeout after $((SECONDS - t0)) s" >&2; return 1; }
        sleep 1
    done
    sleep "$READY_SETTLE_S"
    echo "    ready: inventory_sync reachable and sockets up after $((SECONDS - t0)) s"
}

# The DELETE of the agents is applied asynchronously by authd: a cleanup right after a
# restart can answer "Deleted: N" and still list the agents. Retry until no bench-* is left.
CLEANUP_TRIES="${AB_TEST_CLEANUP_TRIES:-6}"
CLEANUP_SLEEP_S="${AB_TEST_CLEANUP_SLEEP_S:-10}"
cleanup_agents_retry() {  # label
    local try
    for ((try = 1; try <= CLEANUP_TRIES; try++)); do
        "$SCRIPT_DIR/cleanup_agents.sh" >/dev/null && return 0
        (( try < CLEANUP_TRIES )) || break
        echo "ab_indexer: $1: cleanup_agents.sh attempt $try/$CLEANUP_TRIES failed; retrying in ${CLEANUP_SLEEP_S} s" >&2
        sleep "$CLEANUP_SLEEP_S"
    done
    return 1
}

# The probe's first sample with BOTH fields (count and index_total), or fail after the timeout.
BASELINE_TIMEOUT_S="${AB_TEST_BASELINE_TIMEOUT_S:-30}"
wait_probe_baseline() {  # probe.csv
    local deadline=$((SECONDS + BASELINE_TIMEOUT_S))
    until tail -n +2 "$1" 2>/dev/null | grep -qE '^[^,]+,[^,]+,[0-9]+,[0-9]+$'; do
        if (( SECONDS >= deadline )); then
            echo "ab_indexer: the probe took no complete baseline sample (_count and _stats) in ${BASELINE_TIMEOUT_S}s" >&2
            return 1
        fi
        sleep 0.2
    done
}

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
        echo "      wait until the log says \"$READY_LINE\" and both UDS sockets exist (cap ${READY_TIMEOUT_S}s)"
    else
        local log_mark
        log_mark="$(manager_log_mark)"
        "$SCRIPT_DIR/prepare_manager.sh" --side "$side" --side-only --snapshots "$SNAPSHOTS" || return 1
        wait_manager_ready "$log_mark" || {
            echo "ab_indexer: $label: manager not ready: the run is NOT a valid measurement" >&2; return 1; }
    fi
    echo "    provenance: $dir/provenance.txt (sha256 of analysisd, modulesd, lib/*.so; conf validate)"
    echo "    clean the indexer by allow-list: ${CLEAN_ALLOW[*]} (never .wazuh-threatintel-* / .wazuh-cti-consumers)"
    [[ "$mode" == "agent" ]] && echo "    clean bench-* agents: cleanup_agents.sh (up to $CLEANUP_TRIES tries, ${CLEANUP_SLEEP_S}s apart)"
    echo "    probe: indexer_ingest_probe.sh --patterns $patterns$([[ -n "${AB_RAW_PATTERN:-}" && "$mode" == agent ]] && echo ",$AB_RAW_PATTERN") -> $dir/probe.csv"
    case "$resume" in
        after-run) echo "    docker pause $CONTAINER; run the sender; docker unpause $CONTAINER; wait until the count is quiet ${QUIET_S}s (cap ${DRAIN_TIMEOUT_S}s)" ;;
        timed)     echo "    docker pause $CONTAINER; run the sender; docker unpause after ${PAUSE_S}s; wait until the count is quiet ${QUIET_S}s (cap ${DRAIN_TIMEOUT_S}s)" ;;
        *)         echo "    run the sender; wait until the count is quiet ${QUIET_S}s (cap ${DRAIN_TIMEOUT_S}s)" ;;
    esac
    echo "    run_benchmark.sh --scenario $file --label $label --mode $mode --seed $SEED ${AB_RUN_ARGS:-}"
    [[ "$kind" == "drain" ]] && echo "    drain.json: events accepted (ab_report.py accepted), indexer.events.dropped from $ENGINE_API_SOCKET"
    echo "    ab_report.py collect $dir --side $side --scenario $name --index $i --kind $kind${verdicts:+ verdict: $verdicts}"
    $DRY_RUN && return 0

    local probe_patterns="$patterns" rc=0 t_pause="" t_resume="" bench_pid args=()
    [[ -n "${AB_RAW_PATTERN:-}" && "$mode" == "agent" ]] && probe_patterns="$patterns,$AB_RAW_PATTERN"
    mkdir -p "$dir"
    rm -f "$dir/ab_metrics.json" "$dir/drain.json"   # a run that aborts must not leave an older run's numbers
    write_provenance "$dir" "$side"
    clean_indexer || return 1
    # A failed cleanup leaves bench-* agents that make the next enrollment answer 409: abort the run.
    if [[ "$mode" == "agent" ]] && ! cleanup_agents_retry "$label"; then
        echo "ab_indexer: $label: cleanup_agents.sh failed: the run is NOT a valid measurement" >&2
        return 1
    fi

    probe --out "$dir/probe.csv" --patterns "$probe_patterns" &
    PROBE_PID=$!
    trap 'unpause_indexer; kill_probe' EXIT
    # The baseline: _stats/indexing's index_total is cumulative since the node started, so
    # index_total_delta needs a sample taken BEFORE the pause and the sender.
    wait_probe_baseline "$dir/probe.csv" || { abort_run "$label"; return 1; }

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
    wait_quiet "$probe_patterns" || rc=1
    kill_probe
    trap - EXIT
    if [[ -n "$t_resume" ]]; then
        "$PYTHON" -I -c '
import json, sys
t_pause, t_resume, end, final, accepted, dropped, out = sys.argv[1:]
doc = {"t_pause": float(t_pause), "t_resume": float(t_resume), "drain_end": end, "docs_final": int(final)}
try:
    doc.update({k: v for k, v in json.loads(accepted).items() if isinstance(v, int)})
except ValueError:
    pass
doc["engine_events_dropped"] = None if dropped == "null" else int(dropped)
with open(out, "w") as fh:
    json.dump(doc, fh)
    fh.write("\n")
' "$t_pause" "$t_resume" "$DRAIN_END" "${DRAIN_FINAL:--1}" "$(accepted_json "$dir" "$mode")" "$(engine_dropped)" \
            "$dir/drain.json"
    fi
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

# No default credential and no silent -k: a real campaign without them stops here, before the lock.
if ! $DRY_RUN; then
    indexer_resolve_credentials || exit 1
    indexer_resolve_tls || exit 1
fi

# The measurement window is exclusive: re-exec under the lock (a dry run takes none).
if ! $DRY_RUN && [[ -z "${AB_LOCKED:-}" ]]; then
    mkdir -p "$(dirname "$AB_MEASURE_LOCK")"
    if [[ -n "${AB_REEXEC_PRINT:-}" ]]; then   # test hook: show the command, run nothing
        printf 'REEXEC flock -o %s bash %s' "$AB_MEASURE_LOCK" "$0"
        printf ' [%s]' "${ORIG_ARGS[@]}"; printf ' [--locked]\n'
        exit 0
    fi
    # -o: flock keeps the lock and closes its descriptor before running the child, so nothing the run
    # starts (the manager daemons restarted by prepare_manager.sh --side) inherits it.
    AB_LOCKED=1 exec flock -o "$AB_MEASURE_LOCK" "${BASH:-bash}" "$0" "${ORIG_ARGS[@]}" --locked
fi

# One id per real campaign: UTC time + random. ab_report.py report reads only the runs stamped with it.
CAMPAIGN_ID="${AB_TEST_CAMPAIGN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-${RANDOM}${RANDOM}}"
total_runs=0
$DRY_RUN && echo "[dry-run] nothing below touches the manager, the indexer, a container or the lock"
echo "ab_indexer: ${#PLAN[@]} scenario(s), N=$N per side, warm-up $($WARMUP && echo yes || echo no), lock $AB_MEASURE_LOCK"
echo "            snapshots $SNAPSHOTS, indexer container $CONTAINER, verdict: median v2/v1 >= 0.95"
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
