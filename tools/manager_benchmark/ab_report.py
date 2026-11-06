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

  accepted RESULTS_DIR --mode agent|uds
      Prints what the manager ACCEPTED from the sender, 0 when unknown (ab_indexer.sh records it in
      drain.json): in agent mode the stateless events_sent minus the events of the batches remoted
      did not answer 202 (a 503 is not retried by the sender, so those events never reach the
      engine); in uds mode the session documents_sent (attempts, retries included: informative).

  engine-metric NAME
      Reads an engine `POST /metrics/dump` answer on stdin and prints the integer value of the
      global metric NAME (e.g. indexer.events.dropped); exit 1 and nothing printed when absent.

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
INCOMPARABLE if the drain is not comparable (below), PASS otherwise.

The guards that keep the ratio honest (I226):
  * Drain comparability is the INDEXED FRACTION, not the raw document count. Remoted answers some
    stateless batches 503 under the burst and the sender does not retry them, and the ruleset may
    leave part of the sample unclassified (not indexed), so the two sides never index the same
    absolute number of documents. What must match is indexed_fraction = docs_drained / events
    accepted (the events that reached the engine): the medians of the two sides within
    FRACTION_TOLERANCE (1 %, relative) for the scenarios whose verdict is a drain metric
    (docs_per_s_drain, drain_seconds). A side that drops documents indexes a smaller fraction.
  * A drain whose verdict is NOT a document drain (drain-syscollector: sessions/s) must have drained
    the same documents on both sides, medians of docs_drained within DOC_TOLERANCE (1 %). There the
    sender retries every 503, so both sides are offered the same documents; a side that retained fewer
    sessions (abandoned after the sender's retry budget, `sessions_abandoned`) indexes fewer and its
    sessions/s measures how fast it rejected, not how fast it sent.
  * Every run of a drain scenario must record the engine's indexer.events.dropped (ab_indexer.sh
    reads it from the engine API at the end of the run) and it must be 0 on both sides; a drop or
    an unknown value makes the scenario INCOMPARABLE, with the reason in its notes.
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
DRAIN_METRICS = {"docs_per_s_drain", "drain_seconds"}   # judged only on the same indexed fraction
FRACTION_TOLERANCE = 0.01   # the two sides' median indexed_fraction may differ by this (relative)
DOC_NOTE_TOLERANCE = 0.01   # above it, a note: drain_seconds favours the side with fewer documents
DOC_TOLERANCE = 0.01        # sessions drains: the two sides' median docs_drained may differ by this
DROPPED_METRIC = "indexer.events.dropped"

METRIC_ORDER = [
    "docs_per_s_drain", "drain_seconds", "docs_drained", "indexed_fraction", "events_accepted",
    "events_sent", "events_rejected_503", "sessions_per_s", "sessions_abandoned", "events_per_s", "docs_indexed",
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

    A second where any pattern failed to answer its _count is dropped: a hole must not read as a
    count of zero (the drain would look like it restarted). A second whose _count answered but whose
    _stats did not keeps its count, with index_total None (the diagnostic is then unknown, never 0).
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
                except (KeyError, TypeError, ValueError):
                    slot["ok"] = False
                try:
                    if slot["index_total"] is not None:
                        slot["index_total"] += int(row["index_total"])
                except (KeyError, TypeError, ValueError):
                    slot["index_total"] = None
    except OSError:
        return []
    return [{"epoch": e, "count": s["count"], "index_total": s["index_total"]}
            for e, s in sorted(per_second.items()) if s["ok"]]


def index_total_delta(rows: list[dict[str, Any]]) -> int | None:
    """Indexing operations during the run: _stats' index_total is cumulative since the node started
    (a cleanup does not reset it), so the delta needs the baseline the FIRST sample took before the
    pause and the sender. Without it (that sample's _stats did not answer) the delta is unknown: None,
    not the 0 a later baseline gives when the whole drain fits between two samples (E12 A6)."""
    if not rows or rows[0]["index_total"] is None:
        return None
    last = [r["index_total"] for r in rows if r["index_total"] is not None][-1]
    return last - rows[0]["index_total"]


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


def accepted_counts(results_dir: str, mode: str) -> dict[str, int] | None:
    """What the manager accepted from the sender, from its sender_summary.json; None when unknown.

    agent mode: the stateless lane. `events_sent` counts the events of EVERY batch, answered or not;
    a batch answered anything but 202 (in practice remoted's 503 under the burst) is not retried, so
    its events never reach the engine. The batches of one lane have one size (events_per_batch), so
    the rejected events are events_sent * rejected_batches / batches.
    uds mode: the sessions' documents_sent (every attempt's documents: informative, no guard uses it).
    """
    totals = _load_json(os.path.join(results_dir, "sender_summary.json")).get("totals", {})
    try:
        if mode == "agent":
            st = totals.get("stateless", {})
            sent, batches = int(st.get("events_sent", 0) or 0), int(st.get("sent", 0) or 0)
            ok, s503 = int(st.get("s202", 0) or 0), int(st.get("s503", 0) or 0)
            if sent <= 0 or batches <= 0:
                return None
            accepted = round(sent * ok / batches)
            return {"events_sent": sent, "events_accepted": accepted,
                    "events_rejected_503": round(sent * s503 / batches),
                    "events_rejected": sent - accepted}
        docs = int(totals.get("sessions", {}).get("documents_sent", 0) or 0)
        return {"events_sent": docs, "events_accepted": docs} if docs > 0 else None
    except (AttributeError, TypeError, ValueError):
        return None


def accepted_events(results_dir: str, mode: str) -> int:
    """The accepted events (documents in uds mode), 0 when unknown."""
    counts = accepted_counts(results_dir, mode)
    return counts["events_accepted"] if counts else 0


def engine_metric(dump: dict[str, Any], name: str) -> int | None:
    """The integer value of the global metric `name` in an engine /metrics/dump answer, or None."""
    for m in dump.get("global", []) if isinstance(dump, dict) else []:
        if isinstance(m, dict) and m.get("name") == name:
            try:
                return int(float(m.get("value")))
            except (TypeError, ValueError):
                return None
    return None


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
    sess = sender.get("totals", {}).get("sessions", {})
    if isinstance(sess, dict) and sess.get("sent"):
        metrics["sessions_abandoned"] = int(sess.get("retries_exhausted", 0) or 0) + int(sess.get("abandoned_on_drain", 0) or 0)
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
        delta = index_total_delta(rows)
        if delta is not None:
            metrics["index_total_delta"] = delta
    if kind == "drain" and "t_resume" in drain:
        metrics.update(drain_metrics(rows, float(drain["t_resume"])))
    for key in ("events_sent", "events_accepted", "events_rejected_503"):
        if isinstance(drain.get(key), int):
            metrics[key] = drain[key]
    if kind == "drain" and metrics.get("events_accepted", 0) > 0 and "docs_drained" in metrics:
        metrics["indexed_fraction"] = round(metrics["docs_drained"] / metrics["events_accepted"], 6)

    doc = {
        "side": side, "scenario": scenario, "index": index, "kind": kind, "warmup": warmup,
        "verdict_metrics": verdict_metrics, "metrics": metrics,
        "provenance_sha256": provenance_hash(os.path.join(results_dir, "provenance.txt")),
        "campaign": campaign,
    }
    if kind == "drain" and drain:
        doc["drain_end"] = drain.get("drain_end")
        doc["engine_events_dropped"] = drain.get("engine_events_dropped")
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


def drain_guards(entry: dict[str, Any], v1_runs: list[dict[str, Any]], v2_runs: list[dict[str, Any]],
                 verdict_metrics: list[str]) -> bool:
    """The comparability of a drain scenario (I226). Appends the reasons to entry["notes"], records
    the medians in entry["comparability"], and returns True when the verdict metrics are INCOMPARABLE."""
    if entry["kind"] != "drain" or not verdict_metrics or not v1_runs or not v2_runs:
        return False
    bad = False
    comp: dict[str, Any] = {}
    # 1. the engine dropped nothing, on either side, in any measured run
    for side, side_runs in (("v1", v1_runs), ("v2", v2_runs)):
        values = [r.get("engine_events_dropped") for r in side_runs]
        comp[f"{side}_engine_events_dropped"] = values
        unknown = [r.get("index") for r, v in zip(side_runs, values) if not isinstance(v, int)]
        dropped = [(r.get("index"), v) for r, v in zip(side_runs, values) if isinstance(v, int) and v != 0]
        if dropped:
            bad = True
            entry["notes"].append(
                f"drain INCOMPARABLE: side {side} dropped events ({DROPPED_METRIC} = "
                + ", ".join(f"{v} in run {i}" for i, v in dropped) + "): it drains what its queue kept")
        if unknown:
            bad = True
            entry["notes"].append(
                f"drain INCOMPARABLE: side {side} has no {DROPPED_METRIC} for run(s) "
                + ", ".join(str(i) for i in unknown) + " (the engine API did not answer at the end of the run)")
    # 2. the same indexed fraction of the accepted events, when the verdict is a document drain
    if DRAIN_METRICS & set(verdict_metrics):
        fa = [r["metrics"]["indexed_fraction"] for r in v1_runs if "indexed_fraction" in r["metrics"]]
        fb = [r["metrics"]["indexed_fraction"] for r in v2_runs if "indexed_fraction" in r["metrics"]]
        if len(fa) < len(v1_runs) or len(fb) < len(v2_runs):
            bad = True
            entry["notes"].append("drain INCOMPARABLE: indexed_fraction (docs drained / events accepted) "
                                  "missing from a run (no accepted events in its drain.json)")
        if fa and fb:
            ma, mb = statistics.median(fa), statistics.median(fb)
            gap = abs(ma - mb) / max(ma, mb) if max(ma, mb) else 0.0
            comp.update(v1_indexed_fraction=ma, v2_indexed_fraction=mb, fraction_gap=round(gap, 6))
            if round(gap, 6) > FRACTION_TOLERANCE:   # 1 % exactly is within (float noise rounded away)
                bad = True
                entry["notes"].append(
                    f"drain INCOMPARABLE: v1 indexed {ma:.4f} of the accepted events, v2 {mb:.4f} "
                    f"(gap {gap:.2%}, tolerance {FRACTION_TOLERANCE:.0%}): one side lost documents")
        da = [r["metrics"]["docs_drained"] for r in v1_runs if "docs_drained" in r["metrics"]]
        db = [r["metrics"]["docs_drained"] for r in v2_runs if "docs_drained" in r["metrics"]]
        if da and db:
            ma, mb = statistics.median(da), statistics.median(db)
            gap = abs(ma - mb) / max(ma, mb) if max(ma, mb) else 0.0
            if gap > DOC_NOTE_TOLERANCE:
                entry["notes"].append(
                    f"documents drained differ by {gap:.1%} (v1 {ma:g}, v2 {mb:g}: remoted accepted different "
                    "numbers of events); drain_seconds favours the side with fewer, docs_per_s_drain does not")
    else:
        # 3. a sessions drain (the sender retries every 503): the same documents on both sides
        da = [r["metrics"]["docs_drained"] for r in v1_runs if "docs_drained" in r["metrics"]]
        db = [r["metrics"]["docs_drained"] for r in v2_runs if "docs_drained" in r["metrics"]]
        if len(da) < len(v1_runs) or len(db) < len(v2_runs):
            bad = True
            entry["notes"].append("drain INCOMPARABLE: docs_drained missing from a run")
        if da and db:
            ma, mb = statistics.median(da), statistics.median(db)
            gap = abs(ma - mb) / max(ma, mb) if max(ma, mb) else 0.0
            comp.update(v1_docs_drained=ma, v2_docs_drained=mb, docs_gap=round(gap, 6))
            if round(gap, 6) > DOC_TOLERANCE:
                bad = True
                ab_ = [r["metrics"].get("sessions_abandoned") for r in v1_runs]
                bb_ = [r["metrics"].get("sessions_abandoned") for r in v2_runs]
                entry["notes"].append(
                    f"drain INCOMPARABLE: v1 drained {ma:g} documents, v2 {mb:g} (gap {gap:.1%}, tolerance "
                    f"{DOC_TOLERANCE:.0%}); sessions abandoned after the sender's retry budget v1 {ab_}, v2 {bb_}: "
                    "the side that retained fewer sessions indexed fewer documents")
    entry["comparability"] = comp
    return bad


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
        incomparable = drain_guards(entry, v1_runs, v2_runs, verdict_metrics)
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
                if metric in verdict_metrics and incomparable:
                    cell["verdict"] = "INCOMPARABLE"
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
        comp = entry.get("comparability") or {}
        if comp:
            parts = []
            if "v1_indexed_fraction" in comp:
                parts.append(f"indexed fraction v1 {comp['v1_indexed_fraction']:.4f}, v2 {comp['v2_indexed_fraction']:.4f} "
                             f"(gap {comp['fraction_gap']:.2%}, tolerance {FRACTION_TOLERANCE:.0%})")
            if "docs_gap" in comp:
                parts.append(f"docs drained v1 {comp['v1_docs_drained']:g}, v2 {comp['v2_docs_drained']:g} "
                             f"(gap {comp['docs_gap']:.1%}, tolerance {DOC_TOLERANCE:.0%})")
            parts.append(f"{DROPPED_METRIC} v1 {comp.get('v1_engine_events_dropped')}, "
                         f"v2 {comp.get('v2_engine_events_dropped')}")
            lines.append("\nComparability: " + "; ".join(parts))
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

    e = sub.add_parser("accepted", help="print the events the manager accepted from the sender")
    e.add_argument("results_dir")
    e.add_argument("--mode", required=True, choices=("agent", "uds"))
    e.add_argument("--json", action="store_true", help="every count of accepted_counts as JSON ({} when unknown)")

    g = sub.add_parser("engine-metric", help="print one global metric of an engine /metrics/dump read on stdin")
    g.add_argument("name")

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

    if args.command == "accepted":
        if args.json:
            print(json.dumps(accepted_counts(args.results_dir, args.mode) or {}))
        else:
            print(accepted_events(args.results_dir, args.mode))
        return 0

    if args.command == "engine-metric":
        try:
            value = engine_metric(json.load(sys.stdin), args.name)
        except ValueError:
            value = None
        if value is None:
            return 1
        print(value)
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
