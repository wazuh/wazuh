#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Driver of the stage benchmark: builder_stage_bench, already built in Release. Never builds.
#
#   run.sh --bench PATH --out PREFIX [--cpus LIST] [--cpus-p8 LIST] [--runs N] [--events N] [--selfcheck]
#
# Per P in 1, 8 and mode in stage, index: N runs (default 5); per row the median and the IQR of ns_per_op and the median
# of cpu_ns_per_op. A run counts only when its row is valid. --cpus pins the P = 1 rows, --cpus-p8 the P = 8 rows
# (default --cpus; both default none). --selfcheck: 1 run per row of 20000 events.
# Writes PREFIX.csv (every row), PREFIX.log (provenance and every output) and PREFIX-summary.txt.
# Exit: 0 all rows valid, 1 invalid rows or a failed run, 2 usage.
# The performance gate is the engine's end-to-end A/B; this is a diagnostic. The v1 side and its pairs
# were removed with the v1 library.
set -u

usage() {
  sed -n '5p' "$0" | sed 's/^# *//' >&2
  exit 2
}

BENCH="" OUT="" CPUS=none CPUS_P8="" RUNS=5 EVENTS=200000 SELFCHECK=0
while [ $# -gt 0 ]; do
  case $1 in
    --bench) BENCH=${2:-}; shift 2 ;;
    --out) OUT=${2:-}; shift 2 ;;
    --cpus) CPUS=${2:-}; shift 2 ;;
    --cpus-p8) CPUS_P8=${2:-}; shift 2 ;;
    --runs) RUNS=${2:-}; shift 2 ;;
    --events) EVENTS=${2:-}; shift 2 ;;
    --selfcheck) SELFCHECK=1; shift ;;
    *) echo "run.sh: unknown argument '$1'" >&2; usage ;;
  esac
done
{ [ -x "$BENCH" ] && [ -n "$OUT" ]; } || usage
case $RUNS in ""|*[!0-9]*|0|0[0-9]*) echo "run.sh: --runs must be an integer >= 1 (got '$RUNS')" >&2; usage ;; esac
CPUS_P8=${CPUS_P8:-$CPUS}
if [ $SELFCHECK -eq 1 ]; then RUNS=1 EVENTS=20000; fi

CSV="$OUT.csv" LOG="$OUT.log" SUM="$OUT-summary.txt"
: >"$LOG"
: >"$SUM"
"$BENCH" --csv-header >"$CSV" || exit 2
log() { echo "$*" | tee -a "$LOG"; }

log "# run.sh $(date -u +%FT%TZ) runs=$RUNS events=$EVENTS cpus=$CPUS cpus_p8=$CPUS_P8 selfcheck=$SELFCHECK"
log "# host: $(lscpu | sed -n 's/^Model name: *//p' | head -1); nproc $(nproc); load $(cut -d' ' -f1-3 /proc/loadavg)"
log "# sha256 bench $(sha256sum "$BENCH" | cut -d' ' -f1) $BENCH"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# run_one <mode> <P> <run>: sets VALID, NS and CPU from the STAGE row (run from an empty directory).
run_one() {
  local mode=$1 p=$2 run=$3 cpus pin=() out rc row
  if [ "$p" = 1 ]; then cpus=$CPUS; else cpus=$CPUS_P8; fi
  [ "$cpus" = none ] || pin=(taskset -c "$cpus")
  out=$(cd "$WORK" && "${pin[@]}" "$BENCH" --mode "$mode" --producers "$p" --events "$EVENTS" --pair "$run" 2>&1)
  rc=$?
  { echo "## mode=$mode P=$p run=$run (exit $rc)"; echo "$out"; } >>"$LOG"
  row=$(echo "$out" | sed -n 's/^STAGE,//p' | head -1)
  VALID=0 NS=0 CPU=0
  if [ -n "$row" ]; then
    echo "$row" >>"$CSV"
    NS=$(echo "$row" | cut -d, -f5)
    CPU=$(echo "$row" | cut -d, -f6)
    VALID=$(echo "$row" | cut -d, -f16)
  fi
  [ $rc -eq 0 ] || VALID=0
}

# stats <values...>: "median iqr count"
stats() {
  python3 -I -c '
import statistics, sys
r = [float(x) for x in sys.argv[1:]]
if not r:
    print("0.000 0.000 0"); sys.exit()
q = statistics.quantiles(r, n=4, method="inclusive") if len(r) >= 2 else [r[0], r[0], r[0]]
print("%.3f %.3f %d" % (statistics.median(r), q[2] - q[0], len(r)))
' "$@"
}

RC=0
for p in 1 8; do
  for mode in stage index; do
    nss=() cpus_=()
    for i in $(seq 1 "$RUNS"); do
      run_one "$mode" "$p" "$i"
      if [ "$VALID" = 1 ]; then
        nss+=("$NS")
        cpus_+=("$CPU")
        log "# P=$p $mode run $i: $NS ns/op, $CPU cpu ns/op"
      else
        log "!! P=$p $mode run $i: annulled (invalid)"
        RC=1
      fi
    done
    read -r med iqr n <<<"$(stats "${nss[@]}")"
    read -r cmed _ _ <<<"$(stats "${cpus_[@]}")"
    echo "ROW,producers=$p,mode=$mode,median_ns=$med,iqr_ns=$iqr,valid_runs=$n,runs=$RUNS,cpu_median_ns=$cmed" >>"$SUM"
  done
done
log "# load at the end $(cut -d' ' -f1-3 /proc/loadavg)"
cat "$SUM"
exit $RC
