#!/usr/bin/env python3
# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
ab_report.py — Collect and compare the indexer A/B runs (plan 18, E11c).

The A/B runs the same scenario against two builds of the manager, v1 (the pre-v2 sender) and
v2 (the indexer_client one), in ABBA order, and asks whether v2 sends at least as well as v1
(RNF-3, I15 as amended by I204).

Two subcommands:

  collect RESULTS_DIR --side v1|v2 --scenario NAME --index I [--warmup] [--kind drain|fixed]
          [--verdict-metric M ...] [--campaign ID]
      Reads what one run left (sender_summary.json, summary.json, probe.csv, drain.json) and
      writes RESULTS_DIR/ab_metrics.json. ab_indexer.sh calls it after every run.

  expected RESULTS_DIR --mode agent|uds
      Prints the documents the sender says it sent (stateless events_sent in agent mode, session
      documents_sent in uds mode), 0 when unknown: the target ab_indexer.sh waits for.

  report [--root DIR] [--json FILE] [--markdown FILE] [--campaign ID]
      Reads every DIR/results_ab-*/ab_metrics.json (warm-up runs dropped), takes the MEDIAN per
      side and metric, reports the spread of each side and the v2/v1 ratio, and applies the verdict.
      With --campaign only the runs stamped with that id are read (ab_indexer.sh stamps one per
      campaign), so results left by an earlier, longer or aborted campaign cannot reach the median.
      A missing --root is reported and exits 2 (incomplete), like any other missing data.

The verdict (I204), per verdict metric, on the ratio of medians "v2 over v1, oriented so that
more than 1.00 is better for v2" (a time is inverted: v1/v2):

    ratio >= 1.00          PASS
    0.95 <= ratio < 1.00   PASS_WITHIN_NOISE ("dentro del ruido")
    ratio <  0.95          FAIL

It is applied ONLY to the metrics a scenario names as its verdict metrics: docs/s and time to
drain of the drain scenarios, and sessions/s of the invsync drain one. Fixed-rate scenarios are
no-regression runs (latency, CPU, RSS): their ratios are reported with no verdict. The overall
verdict is FAIL if any verdict metric fails, INCOMPLETE if a side has no runs or mixes builds,
INCOMPARABLE if the two sides did not drain the same documents, PASS otherwise.

Two guards keep the ratio honest:
  * The drain metrics (docs_per_s_drain, drain_seconds) are judged only when both sides drained the
    same number of documents, the medians of docs_drained within DOC_TOLERANCE (1 %). A side that
    drops documents (a full queue) drains sooner and would otherwise "win": the verdict is then
    INCOMPARABLE and the note gives the gap.
  * Every run records the sha256 of its provenance snapshot (the binaries of provenance.txt). A side
    whose measured runs come from more than one set (another HEAD, another snapshot) is INCOMPLETE.
Exit status: 0 PASS, 1 FAIL, 2 INCOMPLETE or INCOMPARABLE.
"""
from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import json
import os
import statistics
import sys
from typing import Any

PASS_RATIO = 1.00
NOISE_FLOOR = 0.95          # I204: the median ratio must reach it
HIGH_SPREAD = 0.10          # (max - min) / median of one side above this: ask for N >= 5

# Orientation: for these a bigger number is better, for the rest a smaller one is.
HIGHER_IS_BETTER = {"docs_per_s_drain", "sessions_per_s", "events_per_s", "docs_indexed", "docs_drained"}
DRAIN_METRICS = {"docs_per_s_drain", "drain_seconds"}   # judged only on the same drained documents
DOC_TOLERANCE = 0.01        # the two sides' median docs_drained may differ by this fraction

METRIC_ORDER = [
    "docs_per_s_drain", "drain_seconds", "docs_drained", "sessions_per_s", "events_per_s", "docs_indexed",
    "latency_p50_ms", "latency_p99_ms", "cpu_pct_avg", "rss_mb_max", "index_total_delta",
]


# ---------------------------------------------------------------------------
# collect
# ---------------------------------------------------------------------------
def _load_json(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def read_probe(path: str) -> list[dict[str, float | None]]:
    """probe.csv rows as {epoch, count, index_total} with the patterns summed per second.

    A second where any pattern failed to answer is dropped: a hole must not read as a count of
    zero (the drain would look like it restarted).
    """
    per_second: dict[float, dict[str, Any]] = {}
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                try:
                    epoch = float(row["epoch"])
                except (KeyError, TypeError, ValueError):
                    continue
                slot = per_second.setdefault(epoch, {"count": 0, "index_total": 0, "ok": True})
                try:
                    slot["count"] += int(row["count"])
                    slot["index_total"] += int(row["index_total"])
                except (KeyError, TypeError, ValueError):
                    slot["ok"] = False
    except OSError:
        return []
    return [{"epoch": e, "count": s["count"], "index_total": s["index_total"]}
            for e, s in sorted(per_second.items()) if s["ok"]]


def drain_metrics(rows: list[dict[str, Any]], t_resume: float) -> dict[str, float]:
    """Documents/s during the drain and seconds until it ends, from the probe's `_count` series.

    The drain starts at t_resume (the indexer is answering again) and ends at the last second in
    which the count still grew. docs/s is the growth over that span.
    """
    if not rows:
        return {"docs_drained": 0, "drain_seconds": 0.0, "docs_per_s_drain": 0.0}
    before = [r for r in rows if r["epoch"] <= t_resume]
    base = (before[-1] if before else rows[0])["count"]
    last_t, last_count = t_resume, base
    prev = base
    for r in rows:
        if r["epoch"] <= t_resume:
            continue
        if r["count"] > prev:
            last_t, last_count = r["epoch"], r["count"]
        prev = max(prev, r["count"])
    seconds = max(0.0, last_t - t_resume)
    docs = max(0, last_count - base)
    return {
        "docs_drained": docs,
        "drain_seconds": round(seconds, 3),
        "docs_per_s_drain": round(docs / seconds, 3) if seconds > 0 else 0.0,
    }


def provenance_hash(path: str) -> str | None:
    """sha256 of the binaries a run measured: the sorted `sha256  path` lines of provenance.txt
    (the date and the side label are left out). None when the file is missing or has none."""
    try:
        with open(path, encoding="utf-8") as fh:
            lines = sorted(ln.strip() for ln in fh
                           if len(ln.split()) == 2 and len(ln.split()[0]) == 64
                           and all(c in "0123456789abcdef" for c in ln.split()[0]))
    except OSError:
        return None
    if not lines:
        return None
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def expected_docs(results_dir: str, mode: str) -> int:
    """The documents the sender declares it sent: events for the engine lane, documents for sessions."""
    totals = _load_json(os.path.join(results_dir, "sender_summary.json")).get("totals", {})
    key = ("stateless", "events_sent") if mode == "agent" else ("sessions", "documents_sent")
    try:
        return int(totals.get(key[0], {}).get(key[1], 0) or 0)
    except (TypeError, ValueError):
        return 0


def collect(results_dir: str, side: str, scenario: str, index: str, kind: str,
            warmup: bool, verdict_metrics: list[str], campaign: str | None = None) -> dict[str, Any]:
    sender = _load_json(os.path.join(results_dir, "sender_summary.json"))
    summary = _load_json(os.path.join(results_dir, "summary.json"))
    drain = _load_json(os.path.join(results_dir, "drain.json"))
    rows = read_probe(os.path.join(results_dir, "probe.csv"))

    metrics: dict[str, float] = {}
    through = sender.get("throughput", {})
    for key, name in (("sessions_per_second", "sessions_per_s"), ("events_per_second", "events_per_s")):
        if through.get(key) is not None:
            metrics[name] = float(through[key])
    lat = sender.get("latency_ms", {})
    series = lat.get("session") or lat.get("stateless") or {}
    if series.get("p50") is not None:
        metrics["latency_p50_ms"] = float(series["p50"])
    if series.get("p99") is not None:
        metrics["latency_p99_ms"] = float(series["p99"])
    procs = summary.get("processes", {})
    if procs:
        metrics["cpu_pct_avg"] = round(sum(float(p.get("cpu_pct_avg", 0)) for p in procs.values()), 3)
        metrics["rss_mb_max"] = round(sum(float(p.get("rss_mb_max", 0)) for p in procs.values()), 3)
    if rows:
        metrics["docs_indexed"] = rows[-1]["count"] - rows[0]["count"]
        metrics["index_total_delta"] = rows[-1]["index_total"] - rows[0]["index_total"]
    if kind == "drain" and "t_resume" in drain:
        metrics.update(drain_metrics(rows, float(drain["t_resume"])))

    doc = {
        "side": side, "scenario": scenario, "index": index, "kind": kind, "warmup": warmup,
        "verdict_metrics": verdict_metrics, "metrics": metrics,
        "provenance_sha256": provenance_hash(os.path.join(results_dir, "provenance.txt")),
        "campaign": campaign,
    }
    if kind == "drain" and drain:
        doc["drain_end"] = drain.get("drain_end")
        doc["expected_docs"] = drain.get("expected_docs")
    with open(os.path.join(results_dir, "ab_metrics.json"), "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    return doc


# ---------------------------------------------------------------------------
# compare
# ---------------------------------------------------------------------------
def classify(ratio: float) -> str:
    """The I204 rule on an oriented ratio (more than 1.00 is better for v2)."""
    r = round(ratio, 6)
    if r >= PASS_RATIO:
        return "PASS"
    if r >= NOISE_FLOOR:
        return "PASS_WITHIN_NOISE"
    return "FAIL"


def oriented_ratio(metric: str, v1: float, v2: float) -> float | None:
    """v2/v1 for a rate, v1/v2 for a time, so that more than 1.00 always favours v2."""
    num, den = (v2, v1) if metric in HIGHER_IS_BETTER else (v1, v2)
    if den == 0:
        return None if num == 0 else float("inf")
    return num / den


def spread(values: list[float]) -> float:
    """(max - min) / median: the dispersion between the repetitions of one side."""
    med = statistics.median(values)
    return (max(values) - min(values)) / med if med else 0.0


def compare(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Per scenario and metric: the medians of both sides, their spread, the ratio, the verdict."""
    by_scenario: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for run in runs:
        if run.get("warmup"):
            continue
        by_scenario.setdefault(run["scenario"], {}).setdefault(run["side"], []).append(run)

    scenarios: dict[str, Any] = {}
    overall = "PASS"
    for name, sides in sorted(by_scenario.items()):
        v1_runs, v2_runs = sides.get("v1", []), sides.get("v2", [])
        verdict_metrics = sorted({m for r in v1_runs + v2_runs for m in r.get("verdict_metrics", [])})
        entry: dict[str, Any] = {
            "kind": (v1_runs + v2_runs)[0].get("kind", ""),
            "n_v1": len(v1_runs), "n_v2": len(v2_runs),
            "verdict_metrics": verdict_metrics, "metrics": {}, "notes": [],
        }
        if not v1_runs or not v2_runs:
            entry["verdict"] = "INCOMPLETE"
            entry["notes"].append("a side has no measured run")
        for side, side_runs in (("v1", v1_runs), ("v2", v2_runs)):
            sets = {r.get("provenance_sha256") for r in side_runs}
            if len(sets) > 1:
                entry["verdict"] = "INCOMPLETE"
                entry["notes"].append(
                    f"side {side} mixes {len(sets)} sets of binaries (provenance sha256): "
                    "the runs of different builds or snapshots cannot share a median")
        names = {m for r in v1_runs + v2_runs for m in r["metrics"]}
        docs_gap = None   # relative gap of the sides' median drained documents, None = comparable
        if entry["kind"] == "drain" and DRAIN_METRICS & set(verdict_metrics):
            da = [r["metrics"]["docs_drained"] for r in v1_runs if "docs_drained" in r["metrics"]]
            db = [r["metrics"]["docs_drained"] for r in v2_runs if "docs_drained" in r["metrics"]]
            if da and db:
                ma, mb = statistics.median(da), statistics.median(db)
                gap = abs(ma - mb) / max(ma, mb) if max(ma, mb) else 0.0
                if gap > DOC_TOLERANCE:
                    docs_gap = gap
                    entry["notes"].append(
                        f"drain metrics INCOMPARABLE: v1 drained {ma:g} documents, v2 {mb:g} "
                        f"(gap {gap:.1%}, tolerance {DOC_TOLERANCE:.0%}): the side that drops documents drains sooner")
            elif v1_runs and v2_runs:
                docs_gap = float("nan")
                entry["notes"].append("drain metrics INCOMPARABLE: docs_drained missing from a side")
        for metric in [m for m in METRIC_ORDER if m in names] + sorted(names - set(METRIC_ORDER)):
            a = [r["metrics"][metric] for r in v1_runs if metric in r["metrics"]]
            b = [r["metrics"][metric] for r in v2_runs if metric in r["metrics"]]
            cell: dict[str, Any] = {"v1_values": a, "v2_values": b}
            if a and b:
                cell["v1_median"], cell["v2_median"] = statistics.median(a), statistics.median(b)
                cell["v1_spread"], cell["v2_spread"] = round(spread(a), 4), round(spread(b), 4)
                ratio = oriented_ratio(metric, cell["v1_median"], cell["v2_median"])
                cell["ratio"] = None if ratio is None else round(ratio, 4)
                cell["raw_ratio_v2_over_v1"] = (
                    round(cell["v2_median"] / cell["v1_median"], 4) if cell["v1_median"] else None)
                if metric in verdict_metrics and metric in DRAIN_METRICS and docs_gap is not None:
                    cell["verdict"] = "INCOMPARABLE"
                    cell["docs_gap"] = None if docs_gap != docs_gap else round(docs_gap, 4)
                elif metric in verdict_metrics and ratio is not None:
                    cell["verdict"] = classify(ratio)
                if max(cell["v1_spread"], cell["v2_spread"]) > HIGH_SPREAD:
                    entry["notes"].append(f"{metric}: spread above {HIGH_SPREAD:.0%}, repeat with N >= 5")
            entry["metrics"][metric] = cell
        if "verdict" not in entry:
            verdicts = [c["verdict"] for m, c in entry["metrics"].items() if "verdict" in c]
            if entry["kind"] == "fixed" or not verdict_metrics:
                entry["verdict"] = "NO_VERDICT"
            elif len(verdicts) < len(verdict_metrics):
                entry["verdict"] = "INCOMPLETE"
            elif "FAIL" in verdicts:
                entry["verdict"] = "FAIL"
            elif "INCOMPARABLE" in verdicts:
                entry["verdict"] = "INCOMPARABLE"
            elif "PASS_WITHIN_NOISE" in verdicts:
                entry["verdict"] = "PASS_WITHIN_NOISE"
            else:
                entry["verdict"] = "PASS"
        scenarios[name] = entry
        if entry["verdict"] == "FAIL":
            overall = "FAIL"
        elif entry["verdict"] == "INCOMPLETE" and overall != "FAIL":
            overall = "INCOMPLETE"
        elif entry["verdict"] == "INCOMPARABLE" and overall == "PASS":
            overall = "INCOMPARABLE"
    if not any(e["verdict"] not in ("NO_VERDICT",) for e in scenarios.values()):
        overall = "INCOMPLETE"   # nothing was judged: no scenario, or only fixed-rate ones
    return {"threshold": NOISE_FLOOR, "overall": overall, "scenarios": scenarios}


def load_runs(root: str, campaign: str | None = None) -> list[dict[str, Any]]:
    """Every run under root; with `campaign`, only the runs stamped with that id."""
    runs = []
    for path in sorted(glob.glob(os.path.join(root, "results_ab-*", "ab_metrics.json"))):
        doc = _load_json(path)
        if doc and (campaign is None or doc.get("campaign") == campaign):
            runs.append(doc)
    return runs


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Indexer A/B: v2 against v1",
        "",
        f"Rule (I204): the median ratio v2/v1 of each verdict metric must reach {NOISE_FLOOR:.2f}; "
        "between 0.95 and 1.00 it is reported as within the noise. A time is inverted (v1/v2), so "
        "above 1.00 always favours v2.",
        "",
        f"**Overall: {result['overall']}**",
    ]
    for name, entry in result["scenarios"].items():
        lines += [
            "",
            f"## {name} ({entry['kind']}, n v1={entry['n_v1']} v2={entry['n_v2']}): {entry['verdict']}",
            "",
            "| metric | v1 median | v2 median | v1 spread | v2 spread | ratio | verdict |",
            "|---|---|---|---|---|---|---|",
        ]
        for metric, c in entry["metrics"].items():
            if "ratio" not in c:
                continue
            ratio = "n/a" if c["ratio"] is None else f"{c['ratio']:.3f}"
            lines.append(
                f"| {metric} | {c['v1_median']:g} | {c['v2_median']:g} | {c['v1_spread']:.1%} | "
                f"{c['v2_spread']:.1%} | {ratio} | {c.get('verdict', '-')} |")
        for note in entry["notes"]:
            lines.append(f"\nNote: {note}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    c = sub.add_parser("collect", help="write ab_metrics.json for one run")
    c.add_argument("results_dir")
    c.add_argument("--side", required=True, choices=("v1", "v2"))
    c.add_argument("--scenario", required=True)
    c.add_argument("--index", required=True)
    c.add_argument("--kind", default="fixed", choices=("drain", "fixed"))
    c.add_argument("--warmup", action="store_true")
    c.add_argument("--verdict-metric", action="append", default=[])
    c.add_argument("--campaign", default=None, help="campaign id stamped in ab_metrics.json")

    e = sub.add_parser("expected", help="print the documents the sender says it sent")
    e.add_argument("results_dir")
    e.add_argument("--mode", required=True, choices=("agent", "uds"))

    r = sub.add_parser("report", help="compare the runs under --root")
    r.add_argument("--root", default=os.path.dirname(os.path.abspath(__file__)))
    r.add_argument("--json")
    r.add_argument("--markdown")
    r.add_argument("--campaign", default=None, help="read only the runs of this campaign id")

    args = parser.parse_args(argv)
    if args.command == "collect":
        doc = collect(args.results_dir, args.side, args.scenario, args.index, args.kind,
                      args.warmup, args.verdict_metric, args.campaign)
        print(json.dumps(doc["metrics"], indent=2))
        return 0

    if args.command == "expected":
        print(expected_docs(args.results_dir, args.mode))
        return 0

    if not os.path.isdir(args.root):
        print(f"ab_report: the results directory {args.root} does not exist: nothing to compare "
              "(INCOMPLETE)", file=sys.stderr)
        return 2
    result = compare(load_runs(args.root, args.campaign))
    text = render_markdown(result)
    for out in (args.json, args.markdown):
        if out:
            os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
            fh.write("\n")
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(text)
    return {"PASS": 0, "FAIL": 1}.get(result["overall"], 2)


if __name__ == "__main__":
    sys.exit(main())
