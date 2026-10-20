#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
# Benchmark driver (plan 18, E2c, I58): the v1 bulk transport (HTTPRequest::post, SINGLE) against the v2 transport,
# both already built in Release with -DINDEXER_CLIENT_BENCH=ON. Never builds anything.
#
#   run.sh --v1 PATH --v2 PATH --cpus LIST|none --out PREFIX [--selfcheck] [--fake-status N] [--wazuhext-sha256 SHA]
#
# Writes PREFIX.csv (header + one row per run), PREFIX-summary.txt and PREFIX.log (provenance and every binary's
# output). Normative (default), per mode plain and tls: 5 pairs v1 (normative headers) / v2 c = 1 of 20 s after a 3 s
# warm-up, alternating which side goes first; ratio = median of the valid pairs' v2/v1 (>= 4 valid pairs). Unreliable
# (v1 max/min > 1.03, IQR of the ratios > 0.04 or < 4 valid pairs) => repeated once; grey zone (median in
# [0.94, 0.96)) => 7 pairs of 30 s. Then the informative runs (v2 c = 2/4/8, v1 as shipped) and the D37 probe (TLS).
# --selfcheck: 2 s per side and mode plus the header check on the wire; exit 0 only when every sample is valid and
# the headers match. Exit codes: 0 ok, 1 invalid sample / failed check, 2 usage, 3 another libwazuhext loaded, 4 host
# load never fell to load1 <= 2, 5 a mode stayed unreliable after its repetition (the summary still says so).
set -u

usage() {
  sed -n '6p' "$0" | sed 's/^# *//' >&2
  exit 2
}

V1="" V2="" CPUS="" OUT="" SELFCHECK=0 FAKE_STATUS=200 WANT_SHA=""
while [ $# -gt 0 ]; do
  case $1 in
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
{ [ -x "$V1" ] && [ -x "$V2" ] && [ -n "$CPUS" ] && [ -n "$OUT" ]; } || usage
case $FAKE_STATUS in '' | *[!0-9]*) usage ;; esac

CSV="$OUT.csv"
SUM="$OUT-summary.txt"
LOG="$OUT.log"
mkdir -p "$(dirname "$OUT")"
: >"$SUM"
: >"$LOG"
"$V2" --csv-header >"$CSV" || { echo "run.sh: $V2 --csv-header failed" >&2; exit 2; }

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
      printf "# %s: pinned CPUs idle %.1f %% of the interval (busy = the measurement itself)
", l, d>0 ? 100*(y[1]-x[1])/d : 0}' | tee -a "$LOG"
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
    # Normative: the same headers (name and value). Shipped: differs exactly in these names (the v1 always asks for
    # gzip; DEFAULT_HEADERS sets Accept and Accept-Charset; both sides let curl add 100-continue, I60).
    hn=fail; hs=fail
    [ -s "$h1" ] && cmp -s "$h1" "$h2" && hn=pass
    names=$(diff "$h1s" "$h2" | sed -n 's/^[<>] \([^:]*\):.*/\1/p' | sort -u | tr '\n' ' ')
    [ -s "$h2" ] && [ "$names" = "accept accept-charset accept-encoding " ] && hs=pass
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
