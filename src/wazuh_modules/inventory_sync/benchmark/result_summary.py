#!/usr/bin/env python3
"""
result_summary.py — Merge bench.csv + monitor.csv + logs.csv into summary.json

Reads three CSVs (and an optional scenario JSON with expectations) and writes
a single machine-readable summary plus a short human-readable report.

Inputs:

  --bench    bench.csv   (from benchmark_sender.py)
  --monitor  monitor.csv (from monitor.py)
  --logs     logs.csv    (from log_parser.py; optional)
  --scenario scenarios/burst.json (optional; provides expectations + name)
  --params   results_*/params.json (optional; metadata about the run)
  --out      summary.json (output)

Expectations supported (all optional) under scenario.json["expectations"]:

  rss_mb_max                 (number)  : max allowed RSS
  rss_growth_mb_max          (number)  : max growth from minute-1 to end
  drops_max                  (number)  : max messages_dropped
  status_offline_max         (number)  : max start_ack_offline + end_ack_offline
  reqret_max                 (number)  : max ReqRet count
  latency_p99_ms_max         (number)  : max session-full p99 latency
  session_success_rate_min   (number)  : min completed/started percentage
  manager_must_survive       (bool)    : default true; FAIL if monitor stopped
                                         due to NoSuchProcess

The result is one of: PASS, FAIL, or NEUTRAL (no expectations given).
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
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


# ---------------------------------------------------------------------------
# Aggregations
# ---------------------------------------------------------------------------
def aggregate_bench(rows: list[dict[str, str]]) -> dict[str, Any]:
    if not rows:
        return {}

    fields = [k for k in rows[0].keys() if k not in ("timestamp", "elapsed_s")]
    totals = {k: 0 for k in fields}
    for r in rows:
        for k in fields:
            totals[k] += to_int(r.get(k))
    return totals


def aggregate_monitor(rows: list[dict[str, str]]) -> dict[str, Any]:
    if not rows:
        return {}

    def col(name: str) -> list[float]:
        return [to_float(r.get(name)) for r in rows if r.get(name) not in (None, "")]

    rss   = col("rss_mb")
    vms   = col("vms_mb")
    cpu   = col("cpu_pct")
    mem   = col("mem_pct")
    fds   = col("fds")
    threads = col("threads")

    # Growth: RSS at second 30 (or first sample) → RSS at last sample
    rss_steady = rss[30] if len(rss) > 30 else (rss[0] if rss else 0.0)
    rss_final  = rss[-1] if rss else 0.0
    rss_growth = round(rss_final - rss_steady, 2)

    out = {
        "samples":       len(rows),
        "rss_mb_min":    round(min(rss), 2) if rss else 0.0,
        "rss_mb_max":    round(max(rss), 2) if rss else 0.0,
        "rss_mb_final":  round(rss_final, 2),
        "rss_growth_mb": rss_growth,
        "vms_mb_max":    round(max(vms), 2) if vms else 0.0,
        "vms_mb_final":  round(vms[-1], 2) if vms else 0.0,
        "cpu_pct_avg":   round(sum(cpu) / len(cpu), 2) if cpu else 0.0,
        "cpu_pct_max":   round(max(cpu), 2) if cpu else 0.0,
        "mem_pct_max":   round(max(mem), 2) if mem else 0.0,
        "threads_max":   int(max(threads)) if threads else 0,
        "fds_max":       int(max(fds)) if fds else 0,
    }
    return out


def aggregate_disk(rows: list[dict[str, str]]) -> dict[str, dict[str, float]]:
    """Per-directory min/max/final/growth from `dir_<name>_mb` columns."""
    if not rows:
        return {}
    disk_cols = [k for k in rows[0].keys() if k.startswith("dir_") and k.endswith("_mb")]
    disks: dict[str, dict[str, float]] = {}
    for col in disk_cols:
        vals = [to_float(r.get(col)) for r in rows if r.get(col) not in (None, "")]
        if not vals:
            continue
        name = col.removeprefix("dir_").removesuffix("_mb")
        disks[name] = {
            "mb_min":    round(min(vals), 2),
            "mb_max":    round(max(vals), 2),
            "mb_final":  round(vals[-1], 2),
            "mb_growth": round(vals[-1] - vals[0], 2),
        }
    return disks


def aggregate_logs(rows: list[dict[str, str]]) -> dict[str, Any]:
    if not rows:
        return {}
    fields = [k for k in rows[0].keys() if k not in ("timestamp", "elapsed_s")]
    return {k: sum(to_int(r.get(k)) for r in rows) for k in fields}


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
def evaluate(
    bench: dict[str, Any],
    monitor: dict[str, Any],
    logs: dict[str, Any],
    sender_summary: dict[str, Any],
    expectations: dict[str, Any],
    disks: dict[str, dict[str, float]] | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    """Return (result, [checks]). result ∈ {PASS, FAIL, NEUTRAL}."""
    if not expectations:
        return "NEUTRAL", []

    checks: list[dict[str, Any]] = []

    def chk(name: str, op: str, want: Any, got: Any) -> bool:
        passed = {
            "<=": lambda g, w: g is not None and g <= w,
            ">=": lambda g, w: g is not None and g >= w,
            "==": lambda g, w: g == w,
        }[op](got, want)
        checks.append({"name": name, "op": op, "want": want, "got": got, "pass": bool(passed)})
        return passed

    if "rss_mb_max" in expectations:
        chk("rss_mb_max", "<=", expectations["rss_mb_max"], monitor.get("rss_mb_max"))
    if "rss_growth_mb_max" in expectations:
        chk("rss_growth_mb_max", "<=", expectations["rss_growth_mb_max"], monitor.get("rss_growth_mb"))
    if "drops_max" in expectations:
        drops = bench.get("messages_dropped", 0)
        chk("drops_max", "<=", expectations["drops_max"], drops)
    if "status_offline_max" in expectations:
        offline = bench.get("start_ack_offline", 0) + bench.get("end_ack_offline", 0)
        chk("status_offline_max", "<=", expectations["status_offline_max"], offline)
    if "reqret_max" in expectations:
        chk("reqret_max", "<=", expectations["reqret_max"], bench.get("reqret", 0))
    if "latency_p99_ms_max" in expectations:
        p99 = sender_summary.get("latency_ms", {}).get("session_full", {}).get("p99")
        chk("latency_p99_ms_max", "<=", expectations["latency_p99_ms_max"], p99)
    if "session_success_rate_min" in expectations:
        started = bench.get("sessions_started", 0)
        completed = bench.get("sessions_completed", 0)
        rate = (completed / started * 100.0) if started > 0 else 0.0
        chk("session_success_rate_min", ">=", expectations["session_success_rate_min"], round(rate, 2))

    # Per-directory growth caps. Scenario declares e.g.
    #   "expectations": { "disk_growth_mb_max": { "inventory_sync": 50 } }
    growth_caps = expectations.get("disk_growth_mb_max") or {}
    if disks and growth_caps:
        for name, cap in growth_caps.items():
            got = (disks.get(name) or {}).get("mb_growth")
            chk(f"disk_growth_mb_max[{name}]", "<=", cap, got)

    overall = "PASS" if all(c["pass"] for c in checks) else "FAIL"
    return overall, checks


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
def render_human(summary: dict[str, Any]) -> str:
    bench   = summary["messages"]
    monitor = summary["process"]
    logs    = summary["logs"]
    lat     = summary.get("latency_ms", {})
    result  = summary.get("result", "NEUTRAL")
    name    = summary.get("scenario", "(unnamed scenario)")

    lines = []
    lines.append("=" * 70)
    lines.append(f"  Inventory Sync benchmark — scenario: {name}")
    lines.append("=" * 70)
    lines.append(f"  Result:                          {result}")
    lines.append(f"  Duration:                        {summary.get('duration_sec', 0)} s")
    lines.append("")
    lines.append("  Traffic (sender)")
    lines.append(f"    Messages sent:                 {bench.get('messages_sent', 0):,}")
    lines.append(f"    Sessions started/completed:    "
                 f"{bench.get('sessions_started', 0):,} / {bench.get('sessions_completed', 0):,}")
    lines.append(f"    StartAck ok/offline/error:     "
                 f"{bench.get('start_ack_ok', 0):,} / "
                 f"{bench.get('start_ack_offline', 0):,} / "
                 f"{bench.get('start_ack_error', 0):,}")
    lines.append(f"    EndAck   ok/offline/error/proc:"
                 f" {bench.get('end_ack_ok', 0):,} / "
                 f"{bench.get('end_ack_offline', 0):,} / "
                 f"{bench.get('end_ack_error', 0):,} / "
                 f"{bench.get('end_ack_processing', 0):,}")
    lines.append(f"    ReqRet / missing ranges:       "
                 f"{bench.get('reqret', 0):,} / {bench.get('missing_ranges_total', 0):,}")
    lines.append("")
    lines.append("  Process (monitor)")
    lines.append(f"    RSS min/max/final/growth (MB): "
                 f"{monitor.get('rss_mb_min', 0)} / {monitor.get('rss_mb_max', 0)} / "
                 f"{monitor.get('rss_mb_final', 0)} / {monitor.get('rss_growth_mb', 0)}")
    lines.append(f"    VMS max/final (MB):            "
                 f"{monitor.get('vms_mb_max', 0)} / {monitor.get('vms_mb_final', 0)}")
    lines.append(f"    CPU avg/max (%):               "
                 f"{monitor.get('cpu_pct_avg', 0)} / {monitor.get('cpu_pct_max', 0)}")
    lines.append(f"    Mem % max / Threads / FDs:     "
                 f"{monitor.get('mem_pct_max', 0)} / {monitor.get('threads_max', 0)} / "
                 f"{monitor.get('fds_max', 0)}")
    lines.append("")

    if lat:
        lines.append("  Latency (ms)")
        for kind in ("start_ack", "end_ack", "session_full"):
            p = lat.get(kind, {})
            if p.get("count"):
                lines.append(f"    {kind:14s} count={p['count']:,} "
                             f"p50={p.get('p50')} p95={p.get('p95')} "
                             f"p99={p.get('p99')} max={p.get('max')}")
        lines.append("")

    disks = summary.get("disk") or {}
    if disks:
        lines.append("  Disk (tracked dirs)")
        for name, stats in disks.items():
            lines.append(
                f"    {name:24s} min={stats.get('mb_min', 0)}MB "
                f"max={stats.get('mb_max', 0)}MB "
                f"final={stats.get('mb_final', 0)}MB "
                f"growth={stats.get('mb_growth', 0)}MB"
            )
        lines.append("")

    if logs:
        lines.append("  Logs (manager)")
        for k, v in logs.items():
            if v:
                lines.append(f"    {k:32s} {v}")
        lines.append("")

    checks = summary.get("checks") or []
    if checks:
        lines.append("  Checks vs. expectations")
        for c in checks:
            mark = "PASS" if c["pass"] else "FAIL"
            lines.append(f"    [{mark}] {c['name']:30s} got={c['got']} {c['op']} {c['want']}")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Merge benchmark results into summary.json")
    p.add_argument("--bench",       required=True, help="Path to bench.csv")
    p.add_argument("--monitor",     required=True, help="Path to process monitor CSV (e.g. monitor/wazuh-manager-modulesd.csv)")
    p.add_argument("--disk-csv",    default=None,  help="Path to disk_usage.csv (optional, for disk growth checks)")
    p.add_argument("--logs",        default=None,  help="Path to logs.csv (optional)")
    p.add_argument("--scenario",    default=None,  help="Scenario JSON with expectations (optional)")
    p.add_argument("--sender-json", default=None,  help="benchmark_sender.py summary JSON (with latency)")
    p.add_argument("--params",      default=None,  help="run params.json (optional metadata)")
    p.add_argument("--out",         required=True, help="Output summary JSON")
    p.add_argument("--quiet",       action="store_true", help="Suppress human-readable text")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    bench_rows   = read_csv(args.bench)
    monitor_rows = read_csv(args.monitor)
    disk_rows    = read_csv(args.disk_csv) if args.disk_csv else []
    logs_rows    = read_csv(args.logs) if args.logs else []

    sender_summary: dict[str, Any] = {}
    if args.sender_json and Path(args.sender_json).exists():
        with open(args.sender_json) as fh:
            sender_summary = json.load(fh)

    scenario: dict[str, Any] = {}
    if args.scenario and Path(args.scenario).exists():
        with open(args.scenario) as fh:
            scenario = json.load(fh)

    params: dict[str, Any] = {}
    if args.params and Path(args.params).exists():
        with open(args.params) as fh:
            params = json.load(fh)

    bench   = aggregate_bench(bench_rows)
    monitor = aggregate_monitor(monitor_rows)
    disks   = aggregate_disk(disk_rows if disk_rows else monitor_rows)
    logs    = aggregate_logs(logs_rows)

    # Prefer sender's stored latency (kept across the whole run); fall back to empty
    latency_ms = sender_summary.get("latency_ms", {})
    duration_sec = sender_summary.get("duration_sec") or len(monitor_rows) or len(bench_rows)

    expectations = scenario.get("expectations", {})
    result, checks = evaluate(bench, monitor, logs, sender_summary, expectations,
                              disks=disks)

    summary = {
        "scenario":     scenario.get("name", scenario.get("scenario", "")),
        "result":       result,
        "duration_sec": duration_sec,
        "params":       params,
        "meta":         sender_summary.get("meta", {}),
        "messages":     bench,
        "process":      monitor,
        "disk":         disks,
        "logs":         logs,
        "latency_ms":   latency_ms,
        "expectations": expectations,
        "checks":       checks,
    }

    Path(args.out).write_text(json.dumps(summary, indent=2, default=str))
    logger.info("Wrote %s", args.out)

    if not args.quiet:
        print(render_human(summary))

    return 0 if result != "FAIL" else 1


if __name__ == "__main__":
    sys.exit(main())
