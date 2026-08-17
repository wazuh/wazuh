#!/usr/bin/env python3
"""
result_summary.py — Merge a run's artifacts into one descriptive summary.json.

Reads the sender's bench.csv (per-second cumulative counters) and
sender_summary.json (totals + latency + by_fleet/by_lane), the GET /metrics
scrape (server_metrics.csv), and optionally a process-resource monitor CSV, and
writes a single machine-readable summary plus a short human-readable report.

This is a descriptive aggregator only — there is NO pass/fail logic. The
sender's own exit code already reflects whether the measurement was valid;
this file just collates the numbers for a person or F9c-4's report to read.

Inputs (see docu/09-metrics-and-output.md for the formats):
  --bench          bench.csv                 (per-second cumulative counters)
  --sender-json    sender_summary.json       (totals, latency, by_fleet/by_lane)
  --server-metrics server_metrics.csv        (long-format GET /metrics scrape, optional)
  --monitor        monitor CSV               (process RSS/CPU, optional)
  --params         params.json               (run metadata, optional)
  --out            summary.json              (output)
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", stream=sys.stderr)
logger = logging.getLogger("result_summary")


def read_csv(path: str | None) -> list[dict[str, str]]:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        logger.warning("CSV not found: %s", path)
        return []
    with p.open() as fh:
        return list(csv.DictReader(fh))


def to_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def to_int(v: Any, default: int = 0) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def load_json(path: str | None) -> dict[str, Any]:
    if path and Path(path).exists():
        with open(path) as fh:
            return json.load(fh)
    return {}


# ---------------------------------------------------------------------------
# Aggregations
# ---------------------------------------------------------------------------
def final_bench_row(rows: list[dict[str, str]]) -> dict[str, Any]:
    """bench.csv counters are cumulative, so the last row IS the run total.
    Counter columns are returned as ints; the latency percentile columns as floats."""
    if not rows:
        return {}
    last = rows[-1]
    out: dict[str, Any] = {}
    for k, v in last.items():
        if k in ("timestamp", "mode"):
            out[k] = v
        elif k.endswith("_ms_p50") or k.endswith("_ms_p99") or k == "elapsed_s":
            out[k] = to_float(v)
        else:
            out[k] = to_int(v)
    return out


def aggregate_monitor(rows: list[dict[str, str]]) -> dict[str, Any]:
    if not rows:
        return {}

    def col(name: str) -> list[float]:
        return [to_float(r.get(name)) for r in rows if r.get(name) not in (None, "")]

    rss, cpu, threads, fds = col("rss_mb"), col("cpu_pct"), col("threads"), col("fds")
    rss_steady = rss[30] if len(rss) > 30 else (rss[0] if rss else 0.0)
    return {
        "samples": len(rows),
        "rss_mb_min": round(min(rss), 2) if rss else 0.0,
        "rss_mb_max": round(max(rss), 2) if rss else 0.0,
        "rss_mb_final": round(rss[-1], 2) if rss else 0.0,
        "rss_growth_mb": round((rss[-1] - rss_steady), 2) if rss else 0.0,
        "cpu_pct_avg": round(sum(cpu) / len(cpu), 2) if cpu else 0.0,
        "cpu_pct_max": round(max(cpu), 2) if cpu else 0.0,
        "threads_max": int(max(threads)) if threads else 0,
        "fds_max": int(max(fds)) if fds else 0,
    }


def aggregate_server_metrics(rows: list[dict[str, str]]) -> dict[str, Any]:
    """Aggregate the server's own statistics, in either shape they arrive in.

    Two producers exist and both are supported, because which one ran depends on
    whether the monitor's dependencies were available:
      - the monitor's `stats-api-inventory-sync.csv`: WIDE, one row per scrape,
        one column per metric (this is what a normal run produces);
      - `scrape_metrics.sh`'s `server_metrics.csv`: LONG, one row per metric per
        scrape (`timestamp,elapsed_s,metric,value`), used as a fallback.

    The server's counters are CUMULATIVE since the module started, not per run, so
    the absolute values include every earlier run against the same manager. `delta`
    (last minus first scrape of this run) is therefore what attributes work to THIS
    run; `final` and `peak` are kept for gauges and histogram summaries, where the
    last observation is the meaningful one."""
    if not rows:
        return {}

    first: dict[str, float] = {}
    latest: dict[str, float] = {}
    peak: dict[str, float] = {}

    is_long_format = "metric" in rows[0] and "value" in rows[0]

    def observe(name: str, value: float) -> None:
        first.setdefault(name, value)
        latest[name] = value
        peak[name] = max(peak.get(name, value), value)

    if is_long_format:
        for r in rows:
            m = r.get("metric")
            if not m:
                continue
            observe(m, to_float(r.get("value")))
    else:
        skip = {"timestamp", "elapsed_s", "query_ok", "query_error", "raw_response_json"}
        for r in rows:
            # A failed scrape leaves the metric columns empty; counting it as 0
            # would fake a counter reset and produce a negative delta.
            if r.get("query_ok") not in (None, "", "1"):
                continue
            for name, raw in r.items():
                if name in skip or raw in (None, ""):
                    continue
                observe(name, to_float(raw))
    # A delta is only meaningful for a monotonic counter. Histogram summary fields
    # (percentiles, min, max) are point-in-time distributions: subtracting two of
    # them yields nonsense (a negative "p99 delta"), so they keep only `final`.
    # Both separators, because the two producers name these differently: the long
    # format keeps the metric's dotted name (`vd.lane.time.p99`) while the wide
    # CSV uses column-safe underscores (`vd_lane_time_p99`). Missing one of them
    # silently reintroduces the nonsense it is here to prevent -- a "delta p99".
    distribution = (".p50", ".p90", ".p99", ".min", ".max",
                    "_p50", "_p90", "_p99", "_min", "_max")
    delta = {m: round(latest[m] - first.get(m, 0.0), 3)
             for m in latest if not m.endswith(distribution)}
    return {"delta": delta, "final": latest, "peak": peak}


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
def render_human(summary: dict[str, Any]) -> str:
    meta = summary.get("meta", {})
    totals = summary.get("totals", {})
    sess = totals.get("sessions", {})
    stateless = totals.get("stateless", {})
    scan = totals.get("scan", {})
    control = totals.get("control", {})
    lat = summary.get("latency_ms", {})
    proc = summary.get("process", {})
    name = summary.get("scenario") or "(unnamed scenario)"

    L = []
    L.append("=" * 70)
    L.append(f"  manager_benchmark — scenario: {name}")
    L.append("=" * 70)
    L.append(f"  mode={meta.get('mode','?')}  agents={meta.get('agents_enrolled','?')}/{meta.get('agents_requested','?')}"
             f"  duration={summary.get('duration_sec', 0)}s")
    if meta.get("server_vd_workers") is not None:
        L.append(f"  server_vd_workers={meta.get('server_vd_workers')}")
    L.append("")
    L.append("  Sessions (/stateful)")
    L.append(f"    sent={sess.get('sent',0):,} ok={sess.get('ok',0):,} noop={sess.get('noop',0):,}")
    L.append(f"    400={sess.get('s400',0)} 403={sess.get('s403',0)} 409={sess.get('s409',0)} "
             f"413={sess.get('s413',0)} 500={sess.get('s500',0)} 503={sess.get('s503',0)}"
             f"(retry_after={sess.get('s503_retry_after',0)}) other={sess.get('other',0)}")
    if stateless.get("sent"):
        L.append("  Engine events (/stateless)")
        L.append(f"    batches={stateless.get('sent',0):,} 202={stateless.get('s202',0):,} "
                 f"400={stateless.get('s400',0)} 413={stateless.get('s413',0)} 503={stateless.get('s503',0)} "
                 f"events={stateless.get('events_sent',0):,}")
    if scan.get("sent"):
        # 200 means the re-scan was ADMITTED (queued), not that it ran: the VD
        # module scans afterward, one agent at a time. Whether the scans
        # happened is in modulesd's log (reason=feed_update).
        L.append("  VD re-scan requests (/scan/vd)")
        L.append(f"    sent={scan.get('sent',0):,} 200(queued)={scan.get('s200',0):,} "
                 f"409={scan.get('s409',0)} 503={scan.get('s503',0)} other={scan.get('other',0)}")
    if control.get("notify_ok") or control.get("startup_ok"):
        L.append("  Control (/control)")
        L.append(f"    startup={control.get('startup_ok',0)}/{control.get('startup_ok',0)+control.get('startup_err',0)}"
                 f"  notify={control.get('notify_ok',0)}/{control.get('notify_ok',0)+control.get('notify_err',0)}"
                 f"  shutdown={control.get('shutdown_ok',0)}/{control.get('shutdown_ok',0)+control.get('shutdown_err',0)}")
    L.append("")
    if lat:
        L.append("  Latency (ms)")
        for kind in ("session", "stateless", "scan", "notify", "startup"):
            p = lat.get(kind, {})
            if p.get("count"):
                L.append(f"    {kind:10s} count={p['count']:,} p50={p.get('p50')} p90={p.get('p90')} "
                         f"p99={p.get('p99')} max={p.get('max')}")
        L.append("")
    if proc:
        L.append("  Process (monitor)")
        L.append(f"    RSS min/max/final/growth (MB): {proc.get('rss_mb_min')} / {proc.get('rss_mb_max')} / "
                 f"{proc.get('rss_mb_final')} / {proc.get('rss_growth_mb')}")
        L.append(f"    CPU avg/max (%): {proc.get('cpu_pct_avg')} / {proc.get('cpu_pct_max')}  "
                 f"threads_max={proc.get('threads_max')}  fds_max={proc.get('fds_max')}")
        L.append("")
    sm = summary.get("server_metrics", {}).get("final", {})
    if sm:
        L.append(f"  Server /metrics scraped: {len(sm)} series (see summary.json server_metrics)")
        L.append("")
    L.append("  (descriptive only — no pass/fail; the sender's exit code judges run validity)")
    L.append("=" * 70)
    return "\n".join(L)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Merge a benchmark run's artifacts into summary.json")
    p.add_argument("--bench", required=True, help="bench.csv from the sender")
    p.add_argument("--sender-json", default=None, help="sender_summary.json (totals + latency + by_*)")
    p.add_argument("--server-metrics", default=None, help="server_metrics.csv (GET /metrics scrape)")
    p.add_argument("--monitor", default=None, help="process-resource monitor CSV (optional)")
    p.add_argument("--params", default=None, help="params.json (run metadata)")
    p.add_argument("--out", required=True, help="output summary JSON")
    p.add_argument("--quiet", action="store_true", help="suppress the human-readable text")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    bench_rows = read_csv(args.bench)
    sender = load_json(args.sender_json)
    params = load_json(args.params)
    server_metrics = aggregate_server_metrics(read_csv(args.server_metrics))
    process = aggregate_monitor(read_csv(args.monitor))

    meta = sender.get("meta", {})
    duration = meta.get("duration_sec") or (to_float(bench_rows[-1].get("elapsed_s")) if bench_rows else 0)
    scenario_name = params.get("scenario_name") or meta.get("scenario_name") or ""

    summary = {
        "scenario": scenario_name,
        "duration_sec": duration,
        "params": params,
        "meta": meta,
        "totals": sender.get("totals", {}),
        "throughput": sender.get("throughput", {}),
        "latency_ms": sender.get("latency_ms", {}),
        "by_fleet": sender.get("by_fleet", {}),
        "by_lane": sender.get("by_lane", {}),
        "bench_final": final_bench_row(bench_rows),
        "server_metrics": server_metrics,
        "process": process,
    }

    Path(args.out).write_text(json.dumps(summary, indent=2, default=str))
    logger.info("Wrote %s", args.out)

    if not args.quiet:
        print(render_human(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
