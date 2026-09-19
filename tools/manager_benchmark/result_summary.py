#!/usr/bin/env python3
"""
result_summary.py — Merge a run's artifacts into one descriptive summary.json.

Reads the sender's bench.csv, the run's samples file (samples/metrics.ndjson: every
daemon's statistics, lossless) and the process-resource CSVs, and writes the DERIVED
numbers a person or a report needs.

This is a descriptive aggregator only — there is NO pass/fail logic. The sender's own
exit code already reflects whether the measurement was valid; this file collates.

What it deliberately does NOT do is copy its inputs. summary.json used to embed
params.json verbatim and six of sender_summary.json's seven keys byte-identically, while
dropping the only key that was not available anywhere else — `expected`, the scenario's
verdict. It now carries the verdict and what it computed, and names its inputs rather
than reproducing them; `inputs` in the output says where each one is.

Inputs:
  --bench          bench.csv                 (per-second cumulative counters)
  --sender-json    sender_summary.json       (totals, latency, by_fleet/by_lane, expected)
  --samples        samples/metrics.ndjson    (every daemon's statistics)
  --monitor-dir    monitor/                  (every process CSV)
  --params         params.json               (run metadata)
  --out            summary.json              (output)
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

# bench_samples.py defines the samples format and ships with the monitor that writes it.
# The two tools live in different trees, so the path is made explicit here rather than
# left to whatever PYTHONPATH the caller happened to export -- getting that wrong made
# the samples file silently unreadable and the summary fall back to the legacy CSV.
_BENCH_SAMPLES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "src", "engine", "tools", "devContainer", "scripts",
)
if os.path.isdir(_BENCH_SAMPLES_DIR):
    sys.path.insert(0, os.path.abspath(_BENCH_SAMPLES_DIR))

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


class _Series:
    """The running state of one metric across a run's scrapes.

    Accumulates without keeping every reading, and without converting anything: an int
    stays an int. `to_float()` used to run over every value on the way in, which turned
    `"wazuh-manager-remoted"` into 0.0 -- destroying the reading, not merely mis-summing it
    -- and collapsed a counter stepping from 2**53 to 2**53+1 into a delta of zero, because
    that is the point where a float stops being able to tell consecutive integers apart.
    """

    __slots__ = ("first", "last", "min", "max", "total", "resets", "count")

    def __init__(self, value: Any) -> None:
        self.first = self.last = self.min = self.max = value
        self.total = 0
        self.resets = 0
        self.count = 1

    def observe(self, value: Any) -> None:
        previous = self.last
        if value >= previous:
            self.total += value - previous
        else:
            # A counter only goes down by restarting, so everything up to the new reading
            # is work done since: the daemon came back and started again from zero.
            self.resets += 1
            self.total += value
        self.last = value
        if value < self.min:
            self.min = value
        if value > self.max:
            self.max = value
        self.count += 1


def aggregate_samples(path: str | None) -> dict[str, Any]:
    """Aggregate every source in the run's samples file, one block per daemon.

    What may be computed from a metric depends on what KIND of metric it is, which is why
    the samples file carries the declared type:

      counters  cumulative for the module's lifetime, so `delta` -- the work done during
                THIS run -- is the number that belongs to it. Computed as the sum of the
                rises, so a daemon restarting mid-run does not produce a negative delta:
                the fall is a reset, the work after it still counts, and `resets` says it
                happened.
      levels    gauges and pulls: instantaneous readings. A delta over them is meaningless
                (5 live sessions then 2 is not "-3 sessions"), so they get first/last/
                min/max and no delta at all.
      text      not numbers. They keep their value instead of being coerced to 0.0.

    Only the LAST run in the file is aggregated. The samples file is append-mode and a
    reused label reuses its results directory, so reading it whole would span runs and
    report their combined delta -- while the charts, scoped to the same last run, showed
    only the latest. The returned `run` says which one these numbers belong to.

    A failed scrape contributes NOTHING. It carries no metrics by construction, so there
    are no zeros to mistake for a counter reset; `failed_scrapes` reports how many there
    were, because a source that was unreachable for half the run is a fact about the run.
    A metric the source reported as disabled is skipped for the same reason, and named in
    `disabled` so the omission is visible rather than silent.
    """
    if not path or not Path(path).exists():
        return {}
    try:
        import bench_samples
    except ImportError:
        logger.warning("bench_samples.py not found next to monitor.py; cannot read %s", path)
        return {}

    run_id = bench_samples.last_run_id(path)
    out: dict[str, Any] = {}
    for src_name in bench_samples.SOURCES:
        descriptors = bench_samples.read_descriptors(path, src_name)
        numeric: dict[str, _Series] = {}
        text: dict[str, Any] = {}
        hist_final: dict[str, Any] = {}
        disabled: set = set()
        ok_samples = failed = 0

        for sample in bench_samples.read_samples(path, src=src_name):
            if not sample.get("ok"):
                failed += 1
                continue
            ok_samples += 1
            # observed(), not `m`/`h`: a disabled metric still reports a value and a
            # summary, and folding a stale one in would invent movement that never happened.
            sample_metrics, sample_hists = bench_samples.observed(sample)
            for name, value in sample_metrics.items():
                if not bench_samples.is_numeric(value):
                    text[name] = value
                    continue
                series = numeric.get(name)
                if series is None:
                    numeric[name] = _Series(value)
                else:
                    series.observe(value)
            disabled.update(sample.get("off") or ())
            for name, summary in sample_hists.items():
                if isinstance(summary, dict):
                    hist_final[name] = summary

        if not ok_samples and not failed:
            continue

        counters: dict[str, Any] = {}
        levels: dict[str, Any] = {}
        for name, series in numeric.items():
            declared = bench_samples.type_of(src_name, name, descriptors)
            kind = bench_samples.classify(declared, series.last)
            if kind == bench_samples.KIND_COUNTER:
                counters[name] = {"first": series.first, "last": series.last,
                                  "delta": series.total, "resets": series.resets}
            else:
                levels[name] = {"first": series.first, "last": series.last,
                                "min": series.min, "max": series.max}

        out[src_name] = {
            "run": run_id,
            "samples": ok_samples,
            "failed_scrapes": failed,
            "disabled": sorted(disabled),
            "descriptors": descriptors,
            "counters": counters,
            "levels": levels,
            "text": text,
            "histograms": hist_final,
            # Flat views, kept because reports and older tooling index them by metric name.
            # `delta` holds COUNTERS ONLY -- a level has no delta to report, and putting one
            # here was how "-3 sessions" got published as if it were a measurement.
            "delta": {n: c["delta"] for n, c in counters.items()},
            "final": {n: s.last for n, s in numeric.items()},
            "peak": {n: s.max for n, s in numeric.items()},
        }

    # Reading nothing out of a file that exists is not the same as a run with no metrics,
    # and summary.json cannot tell the two apart: both leave `server_metrics` empty. The
    # likeliest way to get here is regenerating a summary over an archived results
    # directory recorded before this format, which drops a section its own summary.json
    # still has -- exactly the silent drift between tool and data this format exists to
    # end. Say which of the two happened rather than writing {} without a word.
    if not out:
        if run_id is None:
            logger.warning(
                "no daemon statistics in %s: it carries no run marker, so it is not a "
                "samples file this build can read. A results directory recorded before "
                "the samples format is not readable here (see the README, \"A run "
                "recorded before the samples file existed\"); re-run the scenario.", path)
        else:
            logger.warning(
                "no daemon statistics in %s: run %s produced no readable scrape for any "
                "of %s.", path, run_id, ", ".join(sorted(bench_samples.SOURCES)))
    elif run_id is None:
        # Readings with no marker to scope them: every writer emits one, so this is a
        # hand-made or truncated file. It still aggregates, but if it holds two runs
        # their counters are summed -- the very thing the marker prevents.
        logger.warning(
            "%s has readings but no run marker; they cannot be scoped to one run, so a "
            "file holding several runs reports their combined delta.", path)
    return out


def aggregate_all_processes(monitor_dir: str | None) -> dict[str, Any]:
    """Aggregate EVERY process CSV in the monitor directory, not one hand-picked file.

    summary.json used to carry modulesd alone, so a run's other ten processes -- remoted,
    the engine, wazuh-db, the indexer -- were sampled and then never reached the summary
    or any report built on it.
    """
    if not monitor_dir or not Path(monitor_dir).is_dir():
        return {}
    try:
        import bench_samples
        stats_csvs = {s.csv_name for s in bench_samples.SOURCES.values()}
    except ImportError:
        stats_csvs = set()
    non_process = stats_csvs | {"disk_usage.csv", "logs.csv"}

    out: dict[str, Any] = {}
    for csv_path in sorted(Path(monitor_dir).glob("*.csv")):
        if csv_path.name in non_process:
            continue
        agg = aggregate_monitor(read_csv(str(csv_path)))
        if agg:
            out[csv_path.stem] = agg
    return out


def verdict(sender: dict[str, Any]) -> dict[str, Any]:
    """Condense the sender's `expected` block to the headline.

    A scenario without an expected block asserted nothing, which is not the same as
    passing: `checked` is 0 and `passed` is None rather than True."""
    expected = sender.get("expected") or {}
    if not expected:
        return {"passed": None, "checked": 0, "failed": 0}
    failures = expected.get("failures") or []
    return {
        "passed": expected.get("passed"),
        "checked": expected.get("checked", 0),
        "failed": len(failures),
        # The first failure is what a reader wants at a glance; the rest are in
        # sender_summary.json rather than copied here.
        "first_failure": failures[0] if failures else None,
    }


def relative_inputs(args: argparse.Namespace) -> dict[str, str]:
    """Name the run's other artifacts, relative to the directory summary.json lands in."""
    out_dir = Path(args.out).resolve().parent
    named = {
        "params": args.params,
        "sender_summary": args.sender_json,
        "bench": args.bench,
        "samples": args.samples,
        "monitor_dir": args.monitor_dir,
    }
    inputs: dict[str, str] = {}
    for key, value in named.items():
        if not value:
            continue
        resolved = Path(value).resolve()
        try:
            inputs[key] = str(resolved.relative_to(out_dir))
        except ValueError:
            inputs[key] = str(resolved)
    return inputs


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
def render_human(summary: dict[str, Any], sender: dict[str, Any]) -> str:
    """The human report reads the sender's own file for its totals rather than a copy of
    it inside summary.json -- that copy is exactly the duplication this tool stopped
    writing."""
    meta = sender.get("meta", {})
    totals = sender.get("totals", {})
    sess = totals.get("sessions", {})
    stateless = totals.get("stateless", {})
    scan = totals.get("scan", {})
    control = totals.get("control", {})
    lat = sender.get("latency_ms", {})
    processes = summary.get("processes", {})
    name = summary.get("scenario") or "(unnamed scenario)"

    L = []
    L.append("=" * 70)
    L.append(f"  manager_benchmark — scenario: {name}")
    L.append("=" * 70)
    L.append(f"  mode={meta.get('mode','?')}  agents={meta.get('agents_enrolled','?')}/{meta.get('agents_requested','?')}"
             f"  duration={summary.get('duration_sec', 0)}s")
    if meta.get("server_vd_workers") is not None:
        L.append(f"  server_vd_workers={meta.get('server_vd_workers')}")
    v = summary.get("verdict") or {}
    if v.get("checked"):
        L.append(f"  expected block: {'PASSED' if v.get('passed') else 'FAILED'}"
                 f" ({v.get('checked')} checked, {v.get('failed')} failed)")
        if v.get("first_failure"):
            L.append(f"    first failure: {v['first_failure']}")
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
        # 200 means the re-scan was queued by VD (it will run): the VD module
        # scans afterward, one agent at a time. Whether the scans happened is
        # in modulesd's log (reason=feed_update).
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
    if processes:
        L.append("  Processes (monitor)")
        for proc_name, p in sorted(processes.items(),
                                   key=lambda kv: kv[1].get("rss_mb_max", 0), reverse=True)[:6]:
            L.append(f"    {proc_name:28s} RSS max/growth {p.get('rss_mb_max')}/{p.get('rss_growth_mb')} MB"
                     f"  CPU avg/max {p.get('cpu_pct_avg')}/{p.get('cpu_pct_max')}%")
        L.append("")
    run_ids: set = set()
    for src_name, block in summary.get("server_metrics", {}).items():
        counters = block.get("counters", {})
        moved = sum(1 for c in counters.values() if c.get("delta"))
        resets = sum(c.get("resets", 0) for c in counters.values())
        L.append(f"  {src_name:16s} {block.get('samples',0)} scrapes"
                 f" ({block.get('failed_scrapes',0)} failed),"
                 f" {len(counters)} counters ({moved} moved),"
                 f" {len(block.get('levels', {}))} levels,"
                 f" {len(block.get('histograms', {}))} histograms")
        if resets:
            # A counter only falls by restarting, so this is a daemon that went away and
            # came back during the run -- which changes what the numbers describe.
            L.append(f"  {'':16s} {resets} counter reset(s): a daemon restarted mid-run")
        run_ids.add(block.get("run"))
    for run_id in sorted(r for r in run_ids if r):
        L.append(f"  samples run: {run_id} (a reused label keeps earlier runs in the same file)")
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
    p.add_argument("--samples", default=None, help="samples/metrics.ndjson (every daemon's statistics)")
    p.add_argument("--monitor-dir", default=None, help="monitor/ directory of process CSVs")
    p.add_argument("--params", default=None, help="params.json (run metadata)")
    p.add_argument("--out", required=True, help="output summary JSON")
    p.add_argument("--quiet", action="store_true", help="suppress the human-readable text")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    bench_rows = read_csv(args.bench)
    sender = load_json(args.sender_json)
    params = load_json(args.params)

    server_metrics = aggregate_samples(args.samples)
    processes = aggregate_all_processes(args.monitor_dir)

    meta = sender.get("meta", {})
    duration = meta.get("duration_sec") or (to_float(bench_rows[-1].get("elapsed_s")) if bench_rows else 0)
    scenario_name = params.get("scenario_name") or meta.get("scenario_name") or ""

    summary = {
        "scenario": scenario_name,
        "label": params.get("label", ""),
        "mode": params.get("mode") or meta.get("mode", ""),
        "duration_sec": duration,
        # The scenario's verdict, condensed. It used to be the ONE key this file dropped
        # while copying the other six from sender_summary.json verbatim -- the only
        # judgment in the artifact set, missing from the artifact that collates it. The
        # full failure list stays in sender_summary.json; what is here is the headline.
        "verdict": verdict(sender),
        # Derived here and available nowhere else.
        "bench_final": final_bench_row(bench_rows),
        "server_metrics": server_metrics,
        "processes": processes,
        # Named, not copied: every one of these is a sibling in the run directory, and the
        # paths are relative to it so the directory stays portable once moved or archived.
        "inputs": relative_inputs(args),
    }

    Path(args.out).write_text(json.dumps(summary, indent=2, default=str))
    logger.info("Wrote %s", args.out)

    if not args.quiet:
        print(render_human(summary, sender))
    return 0


if __name__ == "__main__":
    sys.exit(main())
