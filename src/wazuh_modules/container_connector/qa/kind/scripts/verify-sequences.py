#!/usr/bin/env python3
"""No-loss / no-dup verifier for the #36101 spike.

Reads engine file-output NDJSON (standard-wazuh-events-v5 channel) and
checks, per generator pod, that the SEQ counters observed inside the
[--since, --until] window are contiguous (no loss) and unique (no dup).

Generator line format (inside the k8s event's data.log_line):
    SEQ <pod-name> <counter> <epoch.millis> [padding]

Event shapes handled:
  - k8s PoC event: event.original is itself a JSON string
    {"collector":"logcollector","module":"kubernetes","data":{"log_line": "...", ...}}
  - plain passthrough: event.original / message contains the SEQ line directly

Exit code: 0 iff gaps == 0 and dups <= --max-dups (and --require-zero-start
pods, if given, all start at sequence 0).
"""
import argparse
import json
import re
import sys
from datetime import datetime

SEQ_RE = re.compile(r"^SEQ (\S+) (\d+) ([0-9.]+)")


def iso_to_epoch(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def extract(line: str):
    """Return (pod, seq, gen_ts, idx_ts, k8s_meta) or None."""
    try:
        evt = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(evt, dict):
        return None
    orig = (evt.get("event") or {}).get("original") or ""
    payload = None
    k8s = None
    if orig.startswith("{"):
        try:
            inner = json.loads(orig)
            data = inner.get("data") or {}
            payload = data.get("log_line")
            k8s = data.get("kubernetes")
        except (json.JSONDecodeError, AttributeError):
            payload = None
    if payload is None:
        payload = evt.get("message") or orig
    if not isinstance(payload, str):
        return None
    m = SEQ_RE.match(payload)
    if not m:
        return None
    pod, seq, gen_ts = m.group(1), int(m.group(2)), float(m.group(3))
    idx_ts = iso_to_epoch(evt.get("@timestamp", "") or "")
    return pod, seq, gen_ts, idx_ts, k8s


def compact_ranges(values):
    """[1,2,3,7,9,10] -> '1-3,7,9-10'"""
    out, start, prev = [], None, None
    for v in sorted(values):
        if start is None:
            start = prev = v
        elif v == prev + 1:
            prev = v
        else:
            out.append(f"{start}-{prev}" if start != prev else f"{start}")
            start = prev = v
    if start is not None:
        out.append(f"{start}-{prev}" if start != prev else f"{start}")
    return ",".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+", help="NDJSON channel file(s)")
    ap.add_argument("--since", type=float, required=True, help="window start (epoch)")
    ap.add_argument("--until", type=float, required=True, help="window end (epoch)")
    ap.add_argument("--max-dups", type=int, default=0, help="allowed duplicate count")
    ap.add_argument("--expect-pods", type=int, default=0, help="minimum distinct pods expected")
    ap.add_argument("--require-zero-start", action="store_true",
                    help="every pod's min sequence in window must be 0 (S4)")
    ap.add_argument("--zero-start-prefix", default=None,
                    help="only pods whose name starts with this prefix must start at 0")
    ap.add_argument("--require-enrichment", action="store_true",
                    help="fail if k8s metadata fields are missing on k8s events")
    args = ap.parse_args()

    per_pod = {}
    lags = []
    enrichment_bad = 0
    total = 0
    for path in args.files:
        try:
            fh = open(path, "r", errors="replace")
        except OSError as e:
            print(f"!! cannot open {path}: {e}", file=sys.stderr)
            continue
        with fh:
            for line in fh:
                rec = extract(line)
                if rec is None:
                    continue
                pod, seq, gen_ts, idx_ts, k8s = rec
                if not (args.since <= gen_ts <= args.until):
                    continue
                total += 1
                per_pod.setdefault(pod, []).append(seq)
                if idx_ts:
                    lags.append(idx_ts - gen_ts)
                if args.require_enrichment:
                    need = ("namespace", "pod_name", "pod_uid", "container_name")
                    if not (isinstance(k8s, dict) and all(k8s.get(f) for f in need)):
                        enrichment_bad += 1

    gaps_total = 0
    dups_total = 0
    failures = []
    print(f"window [{args.since:.3f} .. {args.until:.3f}] "
          f"({args.until - args.since:.0f}s) events={total} pods={len(per_pod)}")
    for pod in sorted(per_pod):
        seqs = per_pod[pod]
        distinct = set(seqs)
        lo, hi = min(distinct), max(distinct)
        expected = hi - lo + 1
        missing = sorted(set(range(lo, hi + 1)) - distinct)
        dups = len(seqs) - len(distinct)
        gaps_total += len(missing)
        dups_total += dups
        status = "OK" if not missing and not dups else "BAD"
        print(f"  {pod}: range {lo}..{hi} seen={len(seqs)} distinct={len(distinct)} "
              f"gaps={len(missing)} dups={dups} [{status}]")
        if missing:
            print(f"    missing: {compact_ranges(missing)}")
        if args.require_zero_start and lo != 0:
            failures.append(f"{pod} starts at {lo}, expected 0")
        if args.zero_start_prefix and pod.startswith(args.zero_start_prefix) and lo != 0:
            failures.append(f"{pod} starts at {lo}, expected 0")

    if lags:
        lags.sort()
        p = lambda q: lags[min(len(lags) - 1, int(q * len(lags)))]
        print(f"lag: p50={p(0.50):.2f}s p95={p(0.95):.2f}s p99={p(0.99):.2f}s max={lags[-1]:.2f}s")

    if args.expect_pods and len(per_pod) < args.expect_pods:
        failures.append(f"only {len(per_pod)} pods seen, expected >= {args.expect_pods}")
    if gaps_total:
        failures.append(f"{gaps_total} missing sequence(s)")
    if dups_total > args.max_dups:
        failures.append(f"{dups_total} duplicate(s) > allowed {args.max_dups}")
    if enrichment_bad:
        failures.append(f"{enrichment_bad} event(s) with incomplete k8s enrichment")

    if failures:
        print("RESULT: FAIL — " + "; ".join(failures))
        return 1
    print(f"RESULT: PASS (gaps=0 dups={dups_total} <= {args.max_dups})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
