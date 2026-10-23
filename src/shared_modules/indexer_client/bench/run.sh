#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
# Benchmark driver (plan 18, E2c, I58): the v1 bulk transport (HTTPRequest::post, SINGLE) against the v2 transport,
# both already built in Release with -DINDEXER_CLIENT_BENCH=ON. Never builds anything.
#
#   run.sh --v1 PATH --v2 PATH --cpus LIST|none --out PREFIX [--selfcheck] [--fake-status N] [--wazuhext-sha256 SHA]
#   run.sh --suite submit --submit PATH --out PREFIX [--cpus LIST] [--cpus-p8 LIST] [--selfcheck] [--wazuhext-sha256 SHA]
#
# Writes PREFIX.csv (header + one row per run), PREFIX-summary.txt and PREFIX.log (provenance and every binary's
# output). Normative (default), per mode plain and tls: 5 pairs v1 (normative headers) / v2 c = 1 of 20 s after a 3 s
# warm-up, alternating which side goes first; ratio = median of the valid pairs' v2/v1 (>= 4 valid pairs). Unreliable
# (v1 max/min > 1.03, IQR of the ratios > 0.04 or < 4 valid pairs) => repeated once; grey zone (median in
# [0.94, 0.96)) => 7 pairs of 30 s. Then the informative runs (v2 c = 2/4/8, v1 as shipped) and the D37 probe (TLS).
# --selfcheck: 2 s per side and mode plus the header check on the wire; exit 0 only when every sample is valid and
# the headers match. Exit codes: 0 ok, 1 invalid sample / failed check, 2 usage, 3 another libwazuhext loaded, 4 host
# load never fell to load1 <= 2, 5 a mode stayed unreliable after its repetition (the summary still says so).
#
# --suite submit (E6c, RNF-2, I119; the transport suite above is the default and does not change): the submit
# microbenchmark (indexer_client_bench_submit). Rows P = 1, 4, 8 x cb none (handover move), P = 1 x cb noop and
# P = 1 x handover view; per row 5 pairs v1/v2 alternating which side goes first, ratio = ns_per_op v2/v1 (lower is
# better). Gate CA-E6c-8 on P = 1 and P = 8 (cb none, move): median <= 1.05 passes, (1.00, 1.05] is grey; IQR of the
# ratios > 0.04 or < 4 valid pairs => the row is repeated once. At P = 8 a grey or failing clock ratio is settled by
# the median cpu_ns_per_op ratio (noted in the summary). --cpus pins every row, --cpus-p8 the P = 8 row (default
# --cpus; both default none). --selfcheck: 1 pair per row with --events 20000; exit 0 only when every sample is valid.
# Extra exit code: 6 a gate failed.
set -u

usage() {
  sed -n '6,7p' "$0" | sed 's/^# *//' >&2
  exit 2
}

V1="" V2="" CPUS="" OUT="" SELFCHECK=0 FAKE_STATUS=200 WANT_SHA="" SUITE=transport SUBMIT="" CPUS_P8=""
while [ $# -gt 0 ]; do
  case $1 in
    --suite) SUITE=${2:-}; shift 2 ;;
    --submit) SUBMIT=${2:-}; shift 2 ;;
    --cpus-p8) CPUS_P8=${2:-}; shift 2 ;;
    --v1) V1=${2:-}; shift 2 ;;
    --v2) V2=${2:-}; shift 2 ;;
    --cpus) CPUS=${2:-}; shift 2 ;;
    --out) OUT=${2:-}; shift 2 ;;
    --selfcheck) SELFCHECK=1; shift ;;
    --fake-status) FAKE_STATUS=${2:-}; shift 2 ;;
    --wazuhext-sha256) WANT_SHA=${2:-}; shift 2 ;;
    *) echo "run.sh: unknown argument '$1'" >&2; usage ;;
  esac
done
case $SUITE in
  transport) { [ -x "$V1" ] && [ -x "$V2" ] && [ -n "$CPUS" ] && [ -n "$OUT" ]; } || usage ;;
  submit) { [ -x "$SUBMIT" ] && [ -n "$OUT" ]; } || usage; CPUS=${CPUS:-none}; CPUS_P8=${CPUS_P8:-$CPUS} ;;
  *) usage ;;
esac
case $FAKE_STATUS in '' | *[!0-9]*) usage ;; esac

CSV="$OUT.csv"
SUM="$OUT-summary.txt"
LOG="$OUT.log"
mkdir -p "$(dirname "$OUT")"
: >"$SUM"
: >"$LOG"
if [ "$SUITE" = submit ]; then HEADER_BIN=$SUBMIT; else HEADER_BIN=$V2; fi
"$HEADER_BIN" --csv-header >"$CSV" || { echo "run.sh: $HEADER_BIN --csv-header failed" >&2; exit 2; }

if [ "$CPUS" = none ]; then PIN=(); else PIN=(taskset -c "$CPUS"); fi
# I58 values. The BENCH_* overrides exist only to exercise this script quickly; a measurement never sets them (they
# are written to the log).
WARMUP=${BENCH_WARMUP:-3}
NORMATIVE_PAIRS=${BENCH_PAIRS:-5} NORMATIVE_SECS=${BENCH_SECS:-20} GREY_PAIRS=7 GREY_SECS=${BENCH_GREY_SECS:-30}
INFO_SECS=${BENCH_INFO_SECS:-20} SELFCHECK_SECS=2 LOAD_MAX=2 LOAD_WAIT=300
RC=0

log() { echo "$*" | tee -a "$LOG"; }
load1() { cut -d' ' -f1 /proc/loadavg; }
sha() { sha256sum "$1" 2>/dev/null | cut -c1-64; }

# run_side <label> <binary> <args...>: one run; sets ROW (CSV line, empty if none), VALID (0/1), MIBS and HDRS (file
# with the HEADER lines). Appends the row to the CSV and the binary's output to the log.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
n_run=0
run_side() {
  local label=$1 bin=$2; shift 2
  n_run=$((n_run + 1))
  local out="$TMP/run$n_run.out"
  "${PIN[@]}" "$bin" "$@" >"$out" 2>&1
  local rc=$?
  { echo "## $label: $(basename "$bin") $* (exit $rc)"; cat "$out"; } >>"$LOG"
  ROW=$(sed -n 's/^ROW,//p' "$out" | head -1)
  HDRS="$TMP/run$n_run.headers"
  sed -n 's/^HEADER //p' "$out" | sort >"$HDRS"
  if [ -z "$ROW" ]; then
    VALID=0 MIBS=0
    log "!! $label: no row (exit $rc)"
    return
  fi
  echo "$ROW" >>"$CSV"
  VALID=$(echo "$ROW" | cut -d, -f20)
  MIBS=$(echo "$ROW" | cut -d, -f9)
  local got
  got=$(echo "$ROW" | cut -d, -f17)
  if [ -n "$WANT_SHA" ] && [ "$got" != "$WANT_SHA" ]; then
    log "!! $label: $(basename "$bin") loaded libwazuhext $got, expected $WANT_SHA: refusing to measure"
    exit 3
  fi
}

cpu_idle() { # cpu_idle: "idle total" jiffies summed over the pinned CPUs (all CPUs with --cpus none)
  local list=${CPUS//,/ }
  awk -v want="$list" 'BEGIN{n=split(want,w," "); for(i=1;i<=n;i++) k["cpu" w[i]]=1}
    /^cpu[0-9]/ && (want=="none" || ($1 in k)) {t=0; for(i=2;i<=NF;i++) t+=$i; idle+=$5+$6; tot+=t} END{print idle+0, tot+0}' /proc/stat
}
IDLE0=""
idle_mark() { # idle_mark <label>: logs the idle % of the pinned CPUs since the previous mark
  local now; now=$(cpu_idle)
  if [ -n "$IDLE0" ]; then
    awk -v a="$IDLE0" -v b="$now" -v l="$1" 'BEGIN{split(a,x," "); split(b,y," "); d=y[2]-x[2];
      printf "# %s: pinned CPUs idle %.1f %% of the interval (busy = the measurement itself)\n", l, d>0 ? 100*(y[1]-x[1])/d : 0}' | tee -a "$LOG"
  fi
  IDLE0=$now
}

wait_load() { # wait_load <mode>: refuse to start a mode while load1 > LOAD_MAX (waits up to LOAD_WAIT s).
  local waited=0
  while awk -v l="$(load1)" -v m=$LOAD_MAX 'BEGIN{exit !(l>m)}'; do
    if [ $waited -ge $LOAD_WAIT ]; then
      log "!! $1: load1 $(load1) > $LOAD_MAX after ${LOAD_WAIT} s: not starting"
      exit 4
    fi
    sleep 5
    waited=$((waited + 5))
  done
  log "# $1: load before $(cut -d' ' -f1-3 /proc/loadavg) (waited ${waited} s)"
  # Idle of the pinned CPUs over the 2 s before the mode: what the host leaves on the measured cores.
  IDLE0=""; idle_mark "$1 (pre)"; sleep 2; idle_mark "$1: 2 s before the mode"
}

# ---- suite submit (E6c contract §3)
if [ "$SUITE" = submit ]; then
  if [ "$CPUS_P8" = none ]; then PIN8=(); else PIN8=(taskset -c "$CPUS_P8"); fi
  # The BENCH_SUBMIT_* overrides exist only to exercise this script quickly (written to the log).
  SUBMIT_PAIRS=${BENCH_SUBMIT_PAIRS:-5} SUBMIT_EVENTS=${BENCH_SUBMIT_EVENTS:-200000}
  [ $SELFCHECK -eq 1 ] && SUBMIT_PAIRS=1 SUBMIT_EVENTS=20000
  log "# run.sh --suite submit $(date -u +%FT%TZ) selfcheck=$SELFCHECK pairs=$SUBMIT_PAIRS events=$SUBMIT_EVENTS cpus=$CPUS cpus_p8=$CPUS_P8"
  log "# host: $(lscpu | sed -n 's/^Model name: *//p' | head -1); nproc $(nproc)"
  for c in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do cat "$c"; done 2>/dev/null | sort | uniq -c |
    sed 's/^ */# governor: /' | tee -a "$LOG"
  log "# affinity: ${PIN[*]:-none} (P = 8: ${PIN8[*]:-none}); shell Cpus_allowed_list $(sed -n 's/^Cpus_allowed_list:\t*//p' /proc/self/status)"
  log "# sha256 submit $(sha "$SUBMIT") $SUBMIT"
  log "# load $(cut -d' ' -f1-3 /proc/loadavg)"

  # run_submit <label> <producers> <args...>: one run; sets SVALID, SNS (ns_per_op) and SCPU (cpu_ns_per_op).
  run_submit() {
    local label=$1 producers=$2; shift 2
    n_run=$((n_run + 1))
    local out="$TMP/run$n_run.out" rc row got
    if [ "$producers" = 8 ]; then
      "${PIN8[@]}" "$SUBMIT" --producers "$producers" "$@" >"$out" 2>&1
    else
      "${PIN[@]}" "$SUBMIT" --producers "$producers" "$@" >"$out" 2>&1
    fi
    rc=$?
    { echo "## $label: $(basename "$SUBMIT") --producers $producers $* (exit $rc)"; cat "$out"; } >>"$LOG"
    row=$(sed -n 's/^SUBMIT,//p' "$out" | head -1)
    if [ -z "$row" ]; then
      SVALID=0 SNS=0 SCPU=0
      log "!! $label: no row (exit $rc)"
      return
    fi
    echo "$row" >>"$CSV"
    SVALID=$(echo "$row" | awk -F, '{print $NF}')
    SNS=$(echo "$row" | cut -d, -f7)
    SCPU=$(echo "$row" | cut -d, -f8)
    got=$(sed -n 's/.* wazuhext_sha256=\([0-9a-f]*\).*/\1/p' "$out" | head -1)
    if [ -n "$WANT_SHA" ] && [ "$got" != "$WANT_SHA" ]; then
      log "!! $label: loaded libwazuhext $got, expected $WANT_SHA: refusing to measure"
      exit 3
    fi
  }

  # submit_attempt <P> <cb> <handover> <pairs> <tag>: sets SSTATS ("median iqr valid cpu_v1 cpu_v2 cpu_ratio").
  submit_attempt() {
    local p=$1 cb=$2 ho=$3 pairs=$4 tag=$5 i side ok1 ok2 n1 n2 c1 c2 ratios="" cratios="" cpu1="" cpu2=""
    for i in $(seq 1 "$pairs"); do
      if [ $((i % 2)) -eq 1 ]; then order="v1 v2"; else order="v2 v1"; fi
      for side in $order; do
        run_submit "$tag P=$p cb=$cb $ho pair $i $side" "$p" --side $side --cb "$cb" --handover "$ho" \
          --events "$SUBMIT_EVENTS" --pair "$i"
        if [ $side = v1 ]; then ok1=$SVALID n1=$SNS c1=$SCPU; else ok2=$SVALID n2=$SNS c2=$SCPU; fi
      done
      if [ "$ok1" = 1 ] && [ "$ok2" = 1 ]; then
        r=$(awk -v a="$n1" -v b="$n2" 'BEGIN{printf "%.6f", (a>0)?b/a:0}')
        cr=$(awk -v a="$c1" -v b="$c2" 'BEGIN{printf "%.6f", (a>0)?b/a:0}')
        ratios="$ratios $r" cratios="$cratios $cr" cpu1="$cpu1 $c1" cpu2="$cpu2 $c2"
        log "# $tag P=$p cb=$cb $ho pair $i: v1 $n1 ns/op, v2 $n2 ns/op, ratio $r (cpu $c1 / $c2, ratio $cr)"
      else
        log "# $tag P=$p cb=$cb $ho pair $i: annulled (v1 valid=$ok1, v2 valid=$ok2)"
      fi
    done
    SSTATS=$(python3 -I -c '
import statistics, sys
lists = [[float(x) for x in a.split()] for a in sys.argv[1:5]]
r, c1, c2, cr = lists
if not r:
    print("0.000 0.000 0 0.0 0.0 0.000"); sys.exit()
q = statistics.quantiles(r, n=4, method="inclusive") if len(r) >= 2 else [r[0], r[0], r[0]]
print("%.3f %.3f %d %.1f %.1f %.3f" % (statistics.median(r), q[2] - q[0], len(r), statistics.median(c1),
                                       statistics.median(c2), statistics.median(cr)))
' "$ratios" "$cpu1" "$cpu2" "$cratios")
    [ -n "$SSTATS" ] || { log "!! python3 missing or failed: cannot compute the medians"; exit 2; }
    log "# $tag P=$p cb=$cb $ho: ratios [${ratios# }] => median iqr valid cpu_v1 cpu_v2 cpu_ratio = $SSTATS"
  }

  ok=1
  for spec in "1 none move gate" "4 none move info" "8 none move gate" "1 noop move info" "1 none view info"; do
    read -r p cb ho kind <<<"$spec"
    [ $SELFCHECK -eq 1 ] || wait_load "submit P=$p cb=$cb $ho"
    repeated=0 tag=submit
    while :; do
      submit_attempt "$p" "$cb" "$ho" "$SUBMIT_PAIRS" "$tag"
      read -r med iqr vp cpu1 cpu2 cratio <<<"$SSTATS"
      reliable=yes
      # IQR relative to the median (the ratios of this suite may be far from 1; E6c G-diff obj. 5).
      awk -v q="$iqr" -v m="$med" -v n="$vp" -v want="$SUBMIT_PAIRS" 'BEGIN{exit !((m>0 ? q/m : 1)>0.04 || n<(want<4?want:4))}' && reliable=no
      if [ $reliable = no ] && [ $repeated -eq 0 ] && [ $SELFCHECK -eq 0 ]; then
        log "# submit P=$p cb=$cb $ho: unreliable (iqr $iqr, valid $vp): repeating once"
        repeated=1 tag=submit-repeat
        wait_load "submit P=$p cb=$cb $ho (repeat)"
        continue
      fi
      break
    done
    if [ $SELFCHECK -eq 1 ] && [ "$vp" != "$SUBMIT_PAIRS" ]; then ok=0; fi
    gate=info
    if [ "$kind" = gate ] && [ $SELFCHECK -eq 0 ] && [ "$vp" -eq 0 ]; then
      gate=invalid # No valid pair: nothing was measured (E6c G-diff obj. 1).
      RC=6
    elif [ "$kind" = gate ] && [ $SELFCHECK -eq 0 ]; then
      gate=$(awk -v m="$med" 'BEGIN{print (m<=1.00) ? "pass" : (m<=1.05) ? "grey" : "fail"}')
      if [ "$p" = 8 ] && [ "$gate" != pass ]; then
        tie=$(awk -v m="$cratio" 'BEGIN{print (m<=1.05) ? "pass" : "fail"}')
        log "# submit P=8: clock ratio $med is $gate; tie-break by cpu_ns_per_op ratio $cratio => $tie"
        gate="$gate,cpu_tiebreak=$tie"
        [ "$tie" = pass ] || RC=6
      elif [ "$gate" = fail ]; then
        RC=6
      fi
    fi
    [ $reliable = yes ] || { [ $RC -eq 0 ] && RC=5; }
    echo "SUBMIT_ROW,producers=$p,cb=$cb,handover=$ho,median=$med,iqr=$iqr,valid_pairs=$vp,pairs=$SUBMIT_PAIRS,cpu_v1=$cpu1,cpu_v2=$cpu2,cpu_ratio=$cratio,reliable=$reliable,gate=$gate" >>"$SUM"
  done
  log "# load at the end $(cut -d' ' -f1-3 /proc/loadavg)"
  if [ $SELFCHECK -eq 1 ]; then
    echo "SELFCHECK,suite=submit,result=$([ $ok = 1 ] && echo pass || echo fail)" >>"$SUM"
    cat "$SUM"
    [ $ok = 1 ] && exit 0 || exit 1
  fi
  cat "$SUM"
  exit $RC
fi

# ---- provenance
log "# run.sh $(date -u +%FT%TZ) selfcheck=$SELFCHECK fake_status=$FAKE_STATUS cpus=$CPUS"
log "# windows: warmup $WARMUP s, normative $NORMATIVE_PAIRS x $NORMATIVE_SECS s, grey $GREY_PAIRS x $GREY_SECS s, informative $INFO_SECS s"
log "# host: $(lscpu | sed -n 's/^Model name: *//p' | head -1); nproc $(nproc)"
for c in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do cat "$c"; done 2>/dev/null | sort | uniq -c |
  sed 's/^ */# governor: /' | tee -a "$LOG"
log "# affinity: ${PIN[*]:-none}; shell Cpus_allowed_list $(sed -n 's/^Cpus_allowed_list:\t*//p' /proc/self/status)"
log "# sha256 v1 $(sha "$V1") $V1"
log "# sha256 v2 $(sha "$V2") $V2"
log "# load $(cut -d' ' -f1-3 /proc/loadavg)"

# Pre-flight: which libwazuhext each binary maps (and the refusal when it is not the expected one).
for b in "$V1" "$V2"; do
  out=$("${PIN[@]}" "$b" --secs 1 --warmup 0 2>&1)
  wx=$(echo "$out" | sed -n 's/.* wazuhext=\([^ ]*\).*/\1/p' | head -1)
  got=$(echo "$out" | sed -n 's/^ROW,//p' | cut -d, -f17)
  log "# preflight $(basename "$b"): libwazuhext $wx sha256 $got"
  if [ -n "$WANT_SHA" ] && [ "$got" != "$WANT_SHA" ]; then
    log "!! $(basename "$b") loads libwazuhext $got, expected $WANT_SHA: refusing to measure"
    exit 3
  fi
done

if [ $SELFCHECK -eq 1 ]; then
  ok=1
  for mode in plain tls; do
    log "# selfcheck $mode: load before $(cut -d' ' -f1-3 /proc/loadavg)"
    run_side "selfcheck $mode v1 normative" "$V1" --mode $mode --headers normative --secs $SELFCHECK_SECS --warmup 1 \
      --fake-status "$FAKE_STATUS" --print-headers
    v1=$VALID; h1=$HDRS
    run_side "selfcheck $mode v2 c=1" "$V2" --mode $mode --c 1 --secs $SELFCHECK_SECS --warmup 1 \
      --fake-status "$FAKE_STATUS" --print-headers
    v2=$VALID; h2=$HDRS
    run_side "selfcheck $mode v1 shipped" "$V1" --mode $mode --headers shipped --secs $SELFCHECK_SECS --warmup 1 \
      --fake-status "$FAKE_STATUS" --print-headers
    v1s=$VALID; h1s=$HDRS
    # Normative: the same headers (name and value), both with Accept-Encoding: gzip (I117). Shipped: differs exactly in
    # these names (DEFAULT_HEADERS sets Accept and Accept-Charset; both sides let curl add 100-continue, I60).
    hn=fail; hs=fail
    [ -s "$h1" ] && cmp -s "$h1" "$h2" && grep -qx 'accept-encoding: gzip' "$h1" && grep -qx 'accept-encoding: gzip' "$h2" &&
      hn=pass
    names=$(diff "$h1s" "$h2" | sed -n 's/^[<>] \([^:]*\):.*/\1/p' | sort -u | tr '\n' ' ')
    [ -s "$h2" ] && [ "$names" = "accept accept-charset " ] && hs=pass
    log "# selfcheck $mode headers: normative v1 vs v2 $hn; shipped v1 vs v2 differ in [${names% }] => $hs"
    if [ $hn = fail ]; then diff "$h1" "$h2" | sed 's/^/#   /' | tee -a "$LOG"; fi
    echo "SELFCHECK,$mode,v1=$v1,v2=$v2,v1_shipped=$v1s,headers_normative=$hn,headers_shipped=$hs" >>"$SUM"
    { [ "$v1" = 1 ] && [ "$v2" = 1 ] && [ "$v1s" = 1 ] && [ $hn = pass ] && [ $hs = pass ]; } || ok=0
    log "# selfcheck $mode: load after $(cut -d' ' -f1-3 /proc/loadavg)"
  done
  echo "SELFCHECK,result=$([ $ok = 1 ] && echo pass || echo fail)" >>"$SUM"
  cat "$SUM"
  [ $ok = 1 ] && exit 0 || exit 1
fi

# attempt <mode> <pairs> <secs> <tag>: runs the pairs and sets STATS ("median v1_spread iqr valid_pairs").
attempt() {
  local mode=$1 pairs=$2 secs=$3 tag=$4 i a1 a2 r1 r2 v1ok v2ok ratios="" v1s=""
  for i in $(seq 1 "$pairs"); do
    # Alternate which side goes first (v1/v2, v2/v1, ...) so a drift of the host does not favour one side.
    if [ $((i % 2)) -eq 1 ]; then order="v1 v2"; else order="v2 v1"; fi
    for side in $order; do
      if [ $side = v1 ]; then
        run_side "$tag $mode pair $i v1" "$V1" --mode "$mode" --headers normative --secs "$secs" --warmup $WARMUP \
          --pair "$i" --fake-status "$FAKE_STATUS"
        v1ok=$VALID a1=$MIBS
      else
        run_side "$tag $mode pair $i v2" "$V2" --mode "$mode" --c 1 --secs "$secs" --warmup $WARMUP --pair "$i" \
          --fake-status "$FAKE_STATUS"
        v2ok=$VALID a2=$MIBS
      fi
    done
    if [ "$v1ok" = 1 ] && [ "$v2ok" = 1 ]; then
      r=$(awk -v a="$a1" -v b="$a2" 'BEGIN{printf "%.6f", (a>0)?b/a:0}')
      ratios="$ratios $r"
      v1s="$v1s $a1"
      log "# $tag $mode pair $i: v1 $a1 MiB/s, v2 $a2 MiB/s, ratio $r"
    else
      log "# $tag $mode pair $i: annulled (v1 valid=$v1ok, v2 valid=$v2ok)"
    fi
  done
  STATS=$(python3 -I -c '
import statistics, sys
r = [float(x) for x in sys.argv[1].split()]
v = [float(x) for x in sys.argv[2].split()]
if not r:
    print("0.000 0.000 0.000 0"); sys.exit()
med = statistics.median(r)
spread = (max(v) / min(v) - 1) if min(v) > 0 else 9.999
q = statistics.quantiles(r, n=4, method="inclusive") if len(r) >= 2 else [r[0], r[0], r[0]]
print("%.3f %.3f %.3f %d" % (med, spread, q[2] - q[0], len(r)))
' "$ratios" "$v1s")
  [ -n "$STATS" ] || { log "!! python3 missing or failed: cannot compute the medians"; exit 2; }
  log "# $tag $mode: ratios [${ratios# }] => median v1_spread iqr valid = $STATS"
}

for mode in plain tls; do
  wait_load "normative $mode"
  pairs=$NORMATIVE_PAIRS secs=$NORMATIVE_SECS repeated=0 grey=no tag=normative
  while :; do
    attempt "$mode" "$pairs" "$secs" "$tag"
    read -r med spread iqr vp <<<"$STATS"
    reliable=yes
    awk -v s="$spread" -v q="$iqr" -v n="$vp" 'BEGIN{exit !(s>0.03 || q>0.04 || n<4)}' && reliable=no
    if [ $reliable = no ] && [ $repeated -eq 0 ]; then
      log "# $mode: unreliable (v1_spread $spread, iqr $iqr, valid $vp): repeating once"
      repeated=1 tag="$tag-repeat"
      wait_load "normative $mode (repeat)"
      continue
    fi
    if [ $reliable = yes ] && [ $pairs -eq $NORMATIVE_PAIRS ] && awk -v m="$med" 'BEGIN{exit !(m>=0.94 && m<0.96)}'; then
      log "# $mode: median $med in the grey zone [0.94, 0.96): $GREY_PAIRS pairs of $GREY_SECS s"
      pairs=$GREY_PAIRS secs=$GREY_SECS repeated=0 grey=yes tag=grey
      wait_load "normative $mode (grey)"
      continue
    fi
    break
  done
  [ $reliable = yes ] || RC=5
  echo "NORMATIVE,$mode,median=$med,valid_pairs=$vp,pairs=$pairs,secs=$secs,v1_spread=$spread,iqr=$iqr,reliable=$reliable,grey=$grey" >>"$SUM"
  log "# normative $mode: load after $(cut -d' ' -f1-3 /proc/loadavg)"
done

for mode in plain tls; do
  wait_load "informative $mode"
  for c in 2 4 8; do
    run_side "info $mode v2 c=$c" "$V2" --mode $mode --c $c --secs $INFO_SECS --warmup $WARMUP --fake-status "$FAKE_STATUS"
    echo "INFO,$mode,v2,normative,c=$c,mib_s=$(printf '%.1f' "$MIBS"),valid=$VALID" >>"$SUM"
    [ "$VALID" = 1 ] || { log "!! info $mode v2 c=$c invalid"; [ $RC -eq 0 ] && RC=1; }
  done
  run_side "info $mode v1 shipped" "$V1" --mode $mode --headers shipped --secs $INFO_SECS --warmup $WARMUP \
    --fake-status "$FAKE_STATUS"
  echo "INFO,$mode,v1,shipped,c=1,mib_s=$(printf '%.1f' "$MIBS"),valid=$VALID" >>"$SUM"
  [ "$VALID" = 1 ] || { log "!! info $mode v1 shipped invalid"; [ $RC -eq 0 ] && RC=1; }
  log "# informative $mode: load after $(cut -d' ' -f1-3 /proc/loadavg)"
done

log "# probe (D37): load before $(cut -d' ' -f1-3 /proc/loadavg)"
"${PIN[@]}" "$V2" --probe --mode tls >"$TMP/probe.out" 2>&1
prc=$?
{ echo "## probe: $(basename "$V2") --probe --mode tls (exit $prc)"; cat "$TMP/probe.out"; } >>"$LOG"
probe=$(grep '^PROBE,' "$TMP/probe.out" | head -1)
if [ -n "$probe" ]; then echo "$probe" >>"$SUM"; else log "!! probe: no PROBE line (exit $prc)"; fi
if [ "$prc" -ne 0 ] || [ -z "$probe" ]; then log "!! probe exit $prc"; [ $RC -eq 0 ] && RC=1; fi

log "# load at the end $(cut -d' ' -f1-3 /proc/loadavg)"
cat "$SUM"
exit $RC
