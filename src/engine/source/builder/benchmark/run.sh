#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Driver of the stage RNF-2 gate (plan 18, E10b, I198): builder_stage_bench, already built in Release. Never builds.
#
#   run.sh --bench PATH --out PREFIX [--cpus LIST] [--cpus-p8 LIST] [--pairs N] [--events N] [--selfcheck]
#
# Per P in 1, 8 and mode in stage, index: N pairs (default 5) v1/v2, alternating which side goes first; ratio =
# ns_per_op v2/v1 (and cpu_ns_per_op v2/v1). A pair counts only when both rows are valid. The gate (CA-E10b-5) is the
# median stage ratio at P = 1 and P = 8: <= 1.05 passes. The index rows are information: their ratio, and the dilution
# = median v1 index/stage ns_per_op (the share of the stage that index() is on the v1 side). --cpus pins the P = 1
# rows, --cpus-p8 the P = 8 rows (default --cpus; both default none). --selfcheck: 1 pair per row of 20000 events.
# Writes PREFIX.csv (every row), PREFIX.log (provenance and every output) and PREFIX-summary.txt.
# Exit: 0 pass, 1 invalid rows or a failed run, 2 usage, 6 the gate failed.
# I208: the RNF-2 gate is now the engine's end-to-end A/B (E12, RNF-3); the stage verdict here is a reported diagnostic.
set -u

usage() {
  sed -n '5p' "$0" | sed 's/^# *//' >&2
  exit 2
}

BENCH="" OUT="" CPUS=none CPUS_P8="" PAIRS=5 EVENTS=200000 SELFCHECK=0
while [ $# -gt 0 ]; do
  case $1 in
    --bench) BENCH=${2:-}; shift 2 ;;
    --out) OUT=${2:-}; shift 2 ;;
    --cpus) CPUS=${2:-}; shift 2 ;;
    --cpus-p8) CPUS_P8=${2:-}; shift 2 ;;
    --pairs) PAIRS=${2:-}; shift 2 ;;
    --events) EVENTS=${2:-}; shift 2 ;;
    --selfcheck) SELFCHECK=1; shift ;;
    *) echo "run.sh: unknown argument '$1'" >&2; usage ;;
  esac
done
{ [ -x "$BENCH" ] && [ -n "$OUT" ]; } || usage
CPUS_P8=${CPUS_P8:-$CPUS}
if [ $SELFCHECK -eq 1 ]; then PAIRS=1 EVENTS=20000; fi

CSV="$OUT.csv" LOG="$OUT.log" SUM="$OUT-summary.txt"
: >"$LOG"
: >"$SUM"
"$BENCH" --csv-header >"$CSV" || exit 2
log() { echo "$*" | tee -a "$LOG"; }

log "# run.sh $(date -u +%FT%TZ) pairs=$PAIRS events=$EVENTS cpus=$CPUS cpus_p8=$CPUS_P8 selfcheck=$SELFCHECK"
log "# host: $(lscpu | sed -n 's/^Model name: *//p' | head -1); nproc $(nproc); load $(cut -d' ' -f1-3 /proc/loadavg)"
log "# sha256 bench $(sha256sum "$BENCH" | cut -d' ' -f1) $BENCH"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# run_one <side> <mode> <P> <pair>: sets VALID, NS and CPU from the STAGE row (run from an empty directory).
run_one() {
  local side=$1 mode=$2 p=$3 pair=$4 cpus pin=() out rc row
  if [ "$p" = 1 ]; then cpus=$CPUS; else cpus=$CPUS_P8; fi
  [ "$cpus" = none ] || pin=(taskset -c "$cpus")
  out=$(cd "$WORK" && "${pin[@]}" "$BENCH" --side "$side" --mode "$mode" --producers "$p" --events "$EVENTS" \
    --pair "$pair" 2>&1)
  rc=$?
  { echo "## $side mode=$mode P=$p pair=$pair (exit $rc)"; echo "$out"; } >>"$LOG"
  row=$(echo "$out" | sed -n 's/^STAGE,//p' | head -1)
  VALID=0 NS=0 CPU=0
  if [ -n "$row" ]; then
    echo "$row" >>"$CSV"
    NS=$(echo "$row" | cut -d, -f6)
    CPU=$(echo "$row" | cut -d, -f7)
    VALID=$(echo "$row" | cut -d, -f17)
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
  declare -A V1NS=()
  for mode in stage index; do
    ratios=() cratios=()
    for i in $(seq 1 "$PAIRS"); do
      if [ $((i % 2)) -eq 1 ]; then order="v1 v2"; else order="v2 v1"; fi
      for side in $order; do
        run_one "$side" "$mode" "$p" "$i"
        if [ $side = v1 ]; then ok1=$VALID ns1=$NS cpu1=$CPU; else ok2=$VALID ns2=$NS cpu2=$CPU; fi
      done
      if [ "$ok1" = 1 ] && [ "$ok2" = 1 ]; then
        ratios+=("$(awk -v a="$ns1" -v b="$ns2" 'BEGIN{printf "%.6f", b/a}')")
        cratios+=("$(awk -v a="$cpu1" -v b="$cpu2" 'BEGIN{printf "%.6f", b/a}')")
        V1NS[$mode]="${V1NS[$mode]:-} $ns1"
        log "# P=$p $mode pair $i: v1 $ns1 ns/op, v2 $ns2 ns/op, ratio ${ratios[-1]} (cpu ${cratios[-1]})"
      else
        log "!! P=$p $mode pair $i: annulled (v1 valid=$ok1, v2 valid=$ok2)"
        RC=1
      fi
    done
    read -r med iqr n <<<"$(stats "${ratios[@]}")"
    read -r cmed _ _ <<<"$(stats "${cratios[@]}")"
    gate=info
    if [ $mode = stage ] && [ $SELFCHECK -eq 0 ]; then
      if [ "$n" = 0 ]; then
        gate=invalid RC=1
      else
        gate=$(awk -v m="$med" 'BEGIN{print (m<=1.05) ? "pass" : "fail"}')
        [ "$gate" = pass ] || { [ $RC -eq 0 ] && RC=6; }
      fi
    fi
    echo "ROW,producers=$p,mode=$mode,median=$med,iqr=$iqr,valid_pairs=$n,pairs=$PAIRS,cpu_median=$cmed,gate=$gate" >>"$SUM"
  done
  # Dilution: the v1 share of index() in the stage (medians of the valid v1 rows).
  read -r s1 _ _ <<<"$(stats ${V1NS[stage]:-})"
  read -r x1 _ _ <<<"$(stats ${V1NS[index]:-})"
  echo "DILUTION,producers=$p,v1_stage_ns=$s1,v1_index_ns=$x1,index_share=$(awk -v s="$s1" -v x="$x1" 'BEGIN{printf "%.3f", (s>0)?x/s:0}')" >>"$SUM"
  unset V1NS
done
log "# load at the end $(cut -d' ' -f1-3 /proc/loadavg)"
cat "$SUM"
exit $RC
