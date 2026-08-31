#!/usr/bin/env python3
from __future__ import annotations
"""
Graphics generator for Wazuh Manager benchmark results.

Reads bench CSV and monitor CSV files from a results directory and generates
comparison charts.  Supports comparing multiple runs (e.g. before/after fix)
by passing multiple result directories.

Usage:
    # Single run charts
    python3 graphics_generator.py -r ./results -o ./charts

    # Compare two runs (before/after queue limits)
    python3 graphics_generator.py \\
        -r ./results_before::"No limits" \\
        -r ./results_after::"With queue limits" \\
        -o ./comparison_charts

Expected files in each results directory:
    bench.csv     ->  the sender's per-second CUMULATIVE counters
                      (sessions_sent, sessions_ok, sessions_503, documents_sent,
                      session_latency_ms_p50/p99, ...) - see
                      tools/manager_benchmark/tool_simulator/docu/09-metrics-and-output.md
    monitor.csv   ->  timestamp, elapsed_s, cpu_pct, rss_mb, vms_mb,
                      fds, threads, read_bytes, write_bytes
"""

import argparse
import os
import re
import sys

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------
plt.style.use("ggplot")

COLORS = [
    "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728",
    "#9467bd", "#8c564b", "#e377c2", "#7f7f7f",
    "#bcbd22", "#17becf",
]


def run_color(idx: int) -> str:
    return COLORS[idx % len(COLORS)]


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
def label_from_dirname(results_dir: str) -> str:
    name = os.path.basename(os.path.normpath(results_dir))
    name = re.sub(r"^results[_-]?", "", name)
    return name or "run"


def _keep_last_run(df: pd.DataFrame) -> pd.DataFrame:
    """Drop rows from previous runs left over in append-mode CSVs.

    monitor.py / log_parser.py open their CSV in append mode (useful when run
    standalone). If a label is reused, the CSV ends up with multiple
    concatenated runs and elapsed_s resets from 120 → 1 across the boundary.
    Plotting that raw produces a diagonal joining the last sample of the old
    run with t=1 of the new one (the visual artifact reported as "doesn't look
    right"). We slice from the last reset onwards so charts always reflect
    the most recent run.
    """
    if "elapsed_s" not in df.columns or len(df) < 2:
        return df
    series = df["elapsed_s"].astype(float)
    diffs = series.diff()
    # A reset is a strictly negative diff (e.g. 120 -> 1.0 yields -119.0).
    resets = diffs[diffs < 0]
    if resets.empty:
        return df
    last_reset_idx = resets.index[-1]
    return df.loc[last_reset_idx:].reset_index(drop=True)


def load_bench(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, parse_dates=["timestamp"])
    if "elapsed_s" not in df.columns:
        df["elapsed_s"] = range(len(df))
    return _keep_last_run(df)


def load_monitor(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, parse_dates=["timestamp"])
    if "elapsed_s" not in df.columns:
        df["elapsed_s"] = range(len(df))
    return _keep_last_run(df)


# Columns every daemon-stats CSV carries as text; everything else is coerced to numbers so a
# failed scrape (empty cells) plots as a gap instead of poisoning the column's dtype.
_STATS_TEXT_COLS = ("timestamp", "query_error", "raw_response_json")


def _load_stats_csv(path: str, text_cols: tuple[str, ...] = _STATS_TEXT_COLS) -> pd.DataFrame:
    """Load one of the per-daemon stats CSVs written by monitor.py."""
    df = pd.read_csv(path)
    if "elapsed_s" not in df.columns:
        df["elapsed_s"] = range(len(df))
    df = _keep_last_run(df)
    for col in df.columns:
        if col in text_cols:
            continue
        df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def load_remoted_stats(path: str) -> pd.DataFrame:
    """Load stats-api-remoted.csv (remoted's C statistics over the framed socket)."""
    return _load_stats_csv(path, _STATS_TEXT_COLS + ("message", "data_name"))


def load_invsync_stats(path: str) -> pd.DataFrame:
    """Load stats-api-inventory-sync.csv (the module's GET /metrics scrape)."""
    return _load_stats_csv(path)


def load_remoted_module_stats(path: str) -> pd.DataFrame:
    """Load stats-api-remoted-module.csv (the C++ module's GET /metrics scrape)."""
    return _load_stats_csv(path)


def load_analysisd_stats(path: str) -> pd.DataFrame:
    return _load_stats_csv(path)


def parse_result_arg(arg: str) -> tuple[str, str]:
    """Parse 'path::label' into (path, label)."""
    if "::" in arg:
        path, label = arg.rsplit("::", 1)
        return path.strip(), label.strip()
    return arg.strip(), label_from_dirname(arg)


# ---------------------------------------------------------------------------
# Chart helpers
# ---------------------------------------------------------------------------
def plot_timeseries(
    datasets: dict[str, pd.DataFrame],
    y_col: str,
    title: str,
    ylabel: str,
    out_path: str,
    figsize=(14, 6),
    y_min: float | None = None,
):
    fig, ax = plt.subplots(figsize=figsize)
    for idx, (label, df) in enumerate(datasets.items()):
        if y_col not in df.columns:
            continue
        ax.plot(
            df["elapsed_s"], df[y_col],
            label=label, color=run_color(idx),
            linewidth=1.4, alpha=0.85,
        )
    ax.set_title(title, fontsize=14, fontweight="bold")
    ax.set_xlabel("Elapsed time (s)")
    ax.set_ylabel(ylabel)
    if y_min is not None:
        ax.set_ylim(bottom=y_min)
    ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1))
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


def plot_multiline_timeseries(
    df: pd.DataFrame,
    columns: list[str],
    title: str,
    ylabel: str,
    out_path: str,
    figsize=(14, 6),
    y_min: float | None = None,
):
    fig, ax = plt.subplots(figsize=figsize)
    plotted = 0
    for idx, col in enumerate(columns):
        if col not in df.columns:
            continue
        label = col.removeprefix("dir_").removesuffix("_mb").replace("_", "-")
        ax.plot(
            df["elapsed_s"], df[col],
            label=label, color=run_color(idx),
            linewidth=1.4, alpha=0.85,
        )
        plotted += 1
    if plotted == 0:
        plt.close(fig)
        return
    ax.set_title(title, fontsize=14, fontweight="bold")
    ax.set_xlabel("Elapsed time (s)")
    ax.set_ylabel(ylabel)
    if y_min is not None:
        ax.set_ylim(bottom=y_min)
    ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1), fontsize=9)
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


def plot_bar(
    labels: list[str],
    values: list[float],
    colors: list[str],
    title: str,
    ylabel: str,
    out_path: str,
    figsize=(10, 6),
):
    fig, ax = plt.subplots(figsize=figsize)
    x = np.arange(len(labels))
    bars = ax.bar(x, values, color=colors, width=0.5, edgecolor="white")
    for bar, val in zip(bars, values):
        text = f"{val:,.1f}" if isinstance(val, float) else f"{val:,}"
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() * 1.01, text,
                ha="center", va="bottom", fontsize=10)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha="right")
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontsize=14, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


def _rolling(series: pd.Series, window: int) -> pd.Series:
    """Centered rolling mean. min_periods=1 so head/tail aren't NaN."""
    if window <= 1 or len(series) < window:
        return series
    return series.rolling(window=window, center=True, min_periods=1).mean()


def plot_stacked_timeseries(
    datasets: dict[str, pd.DataFrame],
    col_a: str, col_b: str,
    label_a: str, label_b: str,
    ylabel_a: str, ylabel_b: str,
    title: str,
    out_path: str,
    smooth_b_window: int = 1,
):
    """Two metrics per dataset rendered as TWO stacked subplots sharing the X
    axis. Avoids the readability problem of plotting wildly different
    magnitudes (e.g. 10k msgs/s vs 25 sessions/s) on a single Y axis.

    Layout (for N datasets):
      row 0: col_a (one panel per dataset, same Y scale across datasets)
      row 1: col_b (one panel per dataset, same Y scale across datasets)
    """
    n = len(datasets)
    if n == 0:
        return

    fig, axes = plt.subplots(
        2, n,
        figsize=(max(7 * n, 10), 8),
        squeeze=False,
        sharex="col",
    )

    # Shared Y limits per row so comparison across datasets stays honest.
    y_a_max = max((d[col_a].max() for d in datasets.values() if col_a in d.columns),
                  default=0)
    y_b_max = max((d[col_b].max() for d in datasets.values() if col_b in d.columns),
                  default=0)

    for col_idx, (label, df) in enumerate(datasets.items()):
        ax_a = axes[0][col_idx]
        ax_b = axes[1][col_idx]

        if col_a in df.columns:
            ax_a.plot(df["elapsed_s"], df[col_a],
                      color=COLORS[0], linewidth=1.2, alpha=0.85, label=label_a)
            ax_a.fill_between(df["elapsed_s"], df[col_a],
                              alpha=0.18, color=COLORS[0])
            if y_a_max > 0:
                ax_a.set_ylim(0, y_a_max * 1.05)
        ax_a.set_title(label, fontsize=12, fontweight="bold")
        ax_a.set_ylabel(ylabel_a)
        ax_a.legend(loc="upper right", fontsize=9)
        ax_a.grid(True, alpha=0.3)

        if col_b in df.columns:
            series_b = _rolling(df[col_b], smooth_b_window)
            ax_b.plot(df["elapsed_s"], series_b,
                      color=COLORS[2], linewidth=1.4, alpha=0.9,
                      label=label_b + (f" (rolling avg, w={smooth_b_window})"
                                       if smooth_b_window > 1 else ""))
            ax_b.fill_between(df["elapsed_s"], series_b,
                              alpha=0.18, color=COLORS[2])
            if y_b_max > 0:
                ax_b.set_ylim(0, y_b_max * 1.15)
        ax_b.set_xlabel("Elapsed time (s)")
        ax_b.set_ylabel(ylabel_b)
        ax_b.legend(loc="upper right", fontsize=9)
        ax_b.grid(True, alpha=0.3)
        ax_b.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    fig.suptitle(title, fontsize=15, fontweight="bold", y=0.995)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


# Backwards-compat name: the previous chart was an overlay with one Y axis,
# which made the smaller series unreadable. The new implementation does the
# stacked-subplots layout.
plot_dual_axis = plot_stacked_timeseries


# ---------------------------------------------------------------------------
# Metric definitions
# ---------------------------------------------------------------------------
MONITOR_METRICS = [
    ("rss_mb",      "RSS Memory",               "MB"),
    ("vms_mb",      "VMS Memory",               "MB"),
    ("cpu_pct",     "CPU Usage",                 "CPU %"),
    ("fds",         "Open File Descriptors",     "Count"),
    ("threads",     "Thread Count",              "Count"),
    ("read_bytes",  "Cumulative Bytes Read",     "Bytes"),
    ("write_bytes", "Cumulative Bytes Written",  "Bytes"),
]

# The sender's bench.csv (docu/09-metrics-and-output.md). Every count column is
# CUMULATIVE, so these plot as rising curves and a run's total is the LAST value,
# never the sum of the column.
BENCH_METRICS = [
    ("agents_active",         "Agents Active",                    "Agents"),
    ("sessions_sent",         "Sessions Sent (cumulative)",       "Count"),
    ("sessions_ok",           "Sessions 200 (cumulative)",        "Count"),
    ("sessions_503",          "Sessions 503 (cumulative)",        "Count"),
    ("sessions_500",          "Sessions 500 (cumulative)",        "Count"),
    ("sessions_400",          "Sessions 400 (cumulative)",        "Count"),
    ("sessions_403",          "Sessions 403 (cumulative)",        "Count"),
    ("sessions_401",          "Sessions 401 (cumulative)",        "Count"),
    ("documents_sent",        "Documents Sent (cumulative)",      "Count"),
    ("bytes_sent",            "Bytes Sent (cumulative)",          "Bytes"),
    ("transport_errors",      "Transport Errors (cumulative)",    "Count"),
    ("retries_feed",          "Feed Retries (cumulative)",        "Count"),
    ("stateless_sent",        "Engine Batches Sent (cumulative)", "Count"),
    ("events_sent",           "Engine Events Sent (cumulative)",  "Count"),
    ("control_notify_ok",     "Control Notify OK (cumulative)",   "Count"),
    # POST /scan/vd (feed-update re-scan). scan_200 is "queued", not "scanned":
    # the manager answers at admission and scans afterward, one agent at a time.
    ("scan_sent",             "VD Re-scan Requests Sent (cumulative)",     "Count"),
    ("scan_200",              "VD Re-scan Requests Queued (cumulative)",   "Count"),
    ("scan_409",              "VD Re-scan version_mismatch (cumulative)",  "Count"),
    ("scan_503",              "VD Re-scan scan_queue_full (cumulative)",   "Count"),
    ("session_latency_ms_p50", "Session Latency p50",             "ms"),
    ("session_latency_ms_p99", "Session Latency p99",             "ms"),
    ("scan_latency_ms_p99",   "VD Re-scan Admission Latency p99",  "ms"),
]

# inventory_sync_server. Counters are cumulative for the module's lifetime, so
# these read as ever-rising lines; the gauges (shard/lane depth) are the ones
# that show instantaneous pressure. Histogram columns are MICROSECONDS.
INVSYNC_METRICS = [
    ("requests_200",            "Sessions Answered 200",             "Count"),
    ("requests_503",            "Sessions Shed (503)",               "Count"),
    ("requests_500",            "Sessions Failed (500)",             "Count"),
    ("requests_400",            "Sessions Rejected (400)",           "Count"),
    ("requests_403",            "Sessions Rejected (403)",           "Count"),
    ("requests_409",            "Sessions Rejected (409)",           "Count"),
    ("requests_other",          "Sessions Answered Off-contract (other)", "Count"),
    ("docs_indexed",            "Documents Indexed",                 "Count"),
    ("docs_skipped",            "Documents Skipped",                 "Count"),
    ("bytes_ingested",          "Bytes Ingested",                    "Bytes"),
    ("pipeline_shed_total",     "Pipeline Shed (queue full)",        "Count"),
    ("bulk_flushes",            "Group-commit Flushes",              "Count"),
    ("bulk_bytes_total",        "Bytes Flushed in Group Commits",    "Bytes"),
    ("bulk_sessions_total",     "Sessions Answered by Group Commits", "Count"),
    ("shard_depth_sum",         "Sharded Queue Depth (all shards)",  "Items"),
    ("shard_depth_max",         "Sharded Queue Depth (hottest)",     "Items"),
    ("shard_bytes_sum",         "Sharded Queue Bytes (all shards)",  "Bytes"),
    ("shard_bytes_max",         "Sharded Queue Bytes (hottest)",     "Bytes"),
    ("vd_lane_depth",           "VD Scan Lane Depth",                "Sessions"),
    ("vd_capacity_503_total",   "VD Sessions Shed (lane full)",      "Count"),
    ("vd_scans_ok",             "VD Scans Completed",                "Count"),
    ("vd_scans_failed",         "VD Scans Failed",                   "Count"),
    ("vd_scans_skipped",        "VD Scans Skipped (legitimately)",   "Count"),
    ("vd_retry_after_total",    "VD 503s with Retry-After (feed not ready)", "Count"),
    ("vd_offset_mismatch_total", "VD Sessions Rejected (feed-offset mismatch)", "Count"),
    ("session_duration_bulk_p99",      "Session Duration p99 (bulk)",      "microseconds"),
    ("session_duration_immediate_p99", "Session Duration p99 (immediate)", "microseconds"),
    ("vd_lane_time_p99",        "VD Lane Time p99 (all outcomes)",   "microseconds"),
    ("vd_scan_duration_p99",    "VD Scan Duration p99 (scanner only)", "microseconds"),
    # Transport of the shared UDS server. All gauges: instantaneous levels, not growth.
    ("server_budget_available_bytes",   "Transport — In-flight Budget Available", "Bytes"),
    ("server_budget_inflight_bytes",    "Transport — In-flight Bytes Resident",   "Bytes"),
    ("server_budget_inflight_requests", "Transport — In-flight Requests",         "Requests"),
    ("server_sessions_live",     "Transport — Live Connections",            "Connections"),
    ("server_sessions_data",     "Transport — Data-class Connections",      "Connections"),
    ("server_sessions_control",  "Transport — Control-class Connections",   "Connections"),
    ("server_sessions_liveness", "Transport — Liveness-class Connections",  "Connections"),
]

# remoted_module's own registry (admin socket). Counters are cumulative for the module's
# lifetime; the admin.* block is the transport gauges of the admin server itself.
REMOTED_MODULE_METRICS = [
    ("scanvd_requests_total",     "VD Scan Requests Received",            "Count"),
    ("scanvd_accepted",           "VD Scan Requests Queued by VD",        "Count"),
    ("scanvd_queue_full",         "VD Scan Requests Shed (lane full)",    "Count"),
    ("scanvd_indexer_unavailable", "VD Scan Requests Shed (indexer unavailable)", "Count"),
    ("scanvd_vd_error",           "VD Scan Relay Failures (VD unreachable/not ready)", "Count"),
    ("scanvd_version_mismatch",   "VD Scan Requests Rejected (offset mismatch)", "Count"),
    ("control_notify",            "Control — Keepalive Requests",         "Count"),
    ("control_startup",           "Control — Startup Requests",           "Count"),
    ("control_shutdown",          "Control — Shutdown Requests",          "Count"),
    ("control_rejected",          "Control — Malformed Requests Rejected (400)", "Count"),
    ("control_wdb_error",         "Control — wazuh-db Failures",          "Count"),
    ("control_wdb_latency_p99",   "Control — wazuh-db Round-trip p99 (successful)", "microseconds"),
    ("control_task_fetch",        "Control — Task Fetches",               "Count"),
    ("control_task_fetch_error",  "Control — Task Fetch Failures",        "Count"),
    ("control_registry_agents",   "Control — Agents Tracked",             "Agents"),
    ("keystore_agents",           "Keystore — Agents with a Usable Key",  "Agents"),
    ("keystore_entries_skipped",   "Keystore — Unusable client.keys Lines", "Entries"),
    ("keystore_reload_failures_total", "Keystore — client.keys Load Failures", "Count"),
    ("http_stateless_responses_2xx", "POST /stateless — Accepted (2xx)",  "Count"),
    ("http_stateless_responses_503", "POST /stateless — Shed/Failed (503)", "Count"),
    ("http_stateless_latency_p99",   "POST /stateless — End-to-end p99",  "microseconds"),
    ("http_stateful_responses_2xx",  "POST /stateful — Accepted (2xx)",   "Count"),
    ("http_stateful_responses_503",  "POST /stateful — Shed/Failed (503)", "Count"),
    ("http_stateful_latency_p99",    "POST /stateful — End-to-end p99",   "microseconds"),
    ("server_budget_available_bytes", "Public Transport — In-flight Budget Available", "Bytes"),
    ("server_budget_inflight_bytes",  "Public Transport — In-flight Bytes Resident",   "Bytes"),
    ("server_budget_rejected_total",  "Public Transport — Requests Shed by the Budget", "Count"),
    ("forwarder_deferred_inflight",   "Forwarder — Deferred Requests In Flight", "Requests"),
    ("forwarder_deferred_rejected_total", "Forwarder — Requests Shed (slots full)", "Count"),
    ("forwarder_downstream_5xx",      "Forwarder — Downstream 5xx Answers",   "Count"),
    ("forwarder_error_response_timeout", "Forwarder — Downstream Response Timeouts", "Count"),
    ("forwarder_route_mismatch",      "Forwarder — Downstream Route Mismatches (404/405)", "Count"),
    ("download_started",              "POST /download — Transfers Started",   "Count"),
    ("download_bytes_total",          "POST /download — Bytes Offered",       "Bytes"),
    ("download_not_found",            "POST /download — Unknown Group/WPK (404)", "Count"),
    ("admin_sessions_live",       "Admin Socket — Live Connections",      "Connections"),
]

# WHY agents fail authentication, pre-collapse (the wire folds credential failures into one
# generic 401, so only these counters keep the causes apart). Read together: one cause
# dominating names the fix (NTP, re-enrollment, a scanner hammering the listener...).
# Enrollment outcomes read together: one dominating line names the fix (authd down vs a full
# queue vs a validation problem on the agent side).
_ENROLL_OUTCOME_FUNNEL_COLS = [
    "enroll_accepted",
    "enroll_rejected_auth",
    "enroll_rejected_validation",
    "enroll_disabled",
    "enroll_authd_error",
    "enroll_authd_unavailable",
    "enroll_authd_queue_rejected_total",
]

# Depth against its own cap: the pair that says whether authd_max_queue_size is sized right.
_ENROLL_QUEUE_COLS = ["enroll_authd_queue_depth", "enroll_authd_queue_capacity"]

_AUTH_REJECT_FUNNEL_COLS = [
    "auth_reject_unknown_agent",
    "auth_reject_invalid_signature",
    "auth_reject_bad_token",
    "auth_reject_identity_mismatch",
    "auth_reject_clock_skew",
    "auth_reject_unusable_key",
    "auth_reject_address_not_allowed",
    "auth_reject_enrollment_key_unavailable",
    "auth_reject_payload_mismatch",
    "auth_reject_body_too_large",
    "auth_reject_bad_encoding",
    "auth_reject_malformed",
]

# WHY forwarded requests fail, one line per cause. The per-endpoint responses funnels say WHICH
# path is failing; this says which timeout/knob (or which downstream) to look at.
_FWD_ERROR_FUNNEL_COLS = [
    "forwarder_error_connect",
    "forwarder_error_connect_timeout",
    "forwarder_error_write_timeout",
    "forwarder_error_response_timeout",
    "forwarder_error_transport",
    "forwarder_error_protocol",
    "forwarder_error_response_too_large",
    "forwarder_downstream_5xx",
    "forwarder_route_mismatch",
]

# One responses funnel per forwarded endpoint: WHAT the agents were answered. Some cells are
# structurally zero for a given endpoint (kept for a uniform vocabulary).
_HTTP_RESPONSE_ENDPOINTS = ["stateless", "stateful", "stats", "config", "enroll"]
_HTTP_RESPONSE_CODES = ["2xx", "400", "403", "409", "413", "500", "503", "other"]

# The admission split: everything that arrived lands in exactly one of these. remoted is a
# synchronous passthrough of VD's admission, so accepted means "VD queued it and will run it"
# and every rejection was VISIBLE to the agent (a 503 its next notify retries) -- a healthy
# saturated run shows accepted at the lane's capacity and queue_full absorbing the excess,
# with vd_error flat. An indexer outage moves the shed to indexer_unavailable (VD's own
# reported cause, like queue_full) while VD holds what it already queued.
_SCANVD_FUNNEL_COLS = [
    "scanvd_requests_total",
    "scanvd_accepted",
    "scanvd_queue_full",
    "scanvd_indexer_unavailable",
    "scanvd_vd_error",
    "scanvd_version_mismatch",
]

REMOTED_METRICS = [
    ("queues_received_usage", "Remoted Queue Usage", "Usage"),
    (
        "messages_received_breakdown_discarded",
        "Remoted Messages Received Discarded",
        "Count",
    ),
    (
        "messages_received_breakdown_events",
        "Remoted Messages Received Events",
        "Count",
    ),
    (
        "messages_received_breakdown_events_failed",
        "Remoted Messages Received Events Failed",
        "Count",
    ),
    (
        "messages_sent_breakdown_discarded",
        "Remoted Messages Sent Discarded",
        "Count",
    ),
    ("tcp_sessions", "Remoted TCP Sessions", "Count"),
]

ANALYSISD_METRICS = [
    ("server_events_received",              "Events Received (cumulative)",          "Count"),
    ("router_events_processed",             "Router Events Processed",               "Count"),
    ("router_events_dropped",               "Router Events Dropped",                 "Count"),
    ("router_eps_1m",                       "Router EPS (1 min)",                    "Events/s"),
    ("indexer_events_dropped",              "Indexer Events Dropped",                "Count"),
    ("spaces_standard_events_unclassified", "Standard Space — Events Unclassified",  "Count"),
]

# Agent metadata cache metrics. "entries" is an instantaneous gauge (pull); the rest are
# monotonic cumulative counters.
AGENT_CACHE_METRICS = [
    ("agent_cache_entries",    "Agent Cache — Entries (current)",         "Count"),
    ("agent_cache_hits",       "Agent Cache — Hits (cumulative)",         "Count"),
    ("agent_cache_insertions", "Agent Cache — Insertions (cumulative)",   "Count"),
    ("agent_cache_updates",    "Agent Cache — Updates (cumulative)",      "Count"),
    ("agent_cache_evictions",  "Agent Cache — Evictions (cumulative)",    "Count"),
]

# CSVs in a results dir that are NOT per-process samples. Process discovery walks the
# directory and treats every other .csv as "<process>.csv", so a daemon-stats file missing
# from this set gets plotted as if it were a monitored process. One list, used everywhere the
# directory is walked, so adding a scraper is a one-line change here.
STATS_CSV_NAMES = frozenset({
    "disk_usage.csv",
    "logs.csv",
    "stats-api-remoted.csv",
    "stats-api-remoted-module.csv",
    "stats-api-analysisd.csv",
    "stats-api-inventory-sync.csv",
})

EXTRA_PROCESS_COMPONENTS = (
    "wazuh-indexer",
    "wazuh-indexer-engine",
    "wazuh-dashboard",
)
SIMPLE_MONITOR_EXTRA_COMPONENTS = (
    "wazuh-indexer",
    "wazuh-indexer-engine",
)

# Memory is the one axis the indexer JVM cannot share: it sits around 6 GB while every manager
# process stays under ~600 MB, so including it pins the axis and collapses the whole manager
# into an unreadable band at the bottom. Its memory is not lost -- monitor_rss_total_with_indexer
# is the combined view. The indexer-owned engine stays: it runs in the manager's range.
_MEMORY_METRICS = frozenset({"rss_mb", "vms_mb"})
_SCALE_BREAKING_COMPONENTS = frozenset({"wazuh-indexer"})
TOTAL_MONITOR_EXTRA_COMPONENTS = EXTRA_PROCESS_COMPONENTS


# ---------------------------------------------------------------------------
# Main chart generation
# ---------------------------------------------------------------------------
def generate_charts(
    result_dirs: list[tuple[str, str]],
    out_dir: str,
    fmt: str = "png",
) -> None:
    os.makedirs(out_dir, exist_ok=True)

    monitors: dict[str, pd.DataFrame] = {}
    benches: dict[str, pd.DataFrame] = {}
    disk_dfs: dict[str, pd.DataFrame] = {}
    remoted_dfs: dict[str, pd.DataFrame] = {}
    analysisd_dfs: dict[str, pd.DataFrame] = {}
    invsync_dfs: dict[str, pd.DataFrame] = {}
    remoted_module_dfs: dict[str, pd.DataFrame] = {}
    logs: dict[str, pd.DataFrame] = {}
    modulesd_dfs: dict[str, pd.DataFrame] = {}
    # Optional all-in-one components. Kept separate so manager-only charts
    # stay clean; selected combined charts add them back explicitly.
    extra_proc_dfs: dict[str, dict[str, pd.DataFrame]] = {
        name: {} for name in EXTRA_PROCESS_COMPONENTS
    }

    for path, label in result_dirs:
        bench_path = os.path.join(path, "bench.csv")
        monitor_dir = os.path.join(path, "monitor")
        monitor_path = os.path.join(path, "monitor.csv")

        # Disk usage: prefer monitor/ subdir, fall back to root
        disk_path = os.path.join(monitor_dir, "disk_usage.csv")
        if not os.path.isfile(disk_path):
            disk_path = os.path.join(path, "disk_usage.csv")

        # logs.csv: prefer monitor/ subdir, fall back to root
        logs_path = os.path.join(monitor_dir, "logs.csv")
        if not os.path.isfile(logs_path):
            logs_path = os.path.join(path, "logs.csv")

        # Remoted API stats: prefer monitor/ subdir, fall back to root
        remoted_stats_path = os.path.join(monitor_dir, "stats-api-remoted.csv")
        if not os.path.isfile(remoted_stats_path):
            remoted_stats_path = os.path.join(path, "stats-api-remoted.csv")

        # Analysisd API stats: prefer monitor/ subdir, fall back to root
        analysisd_stats_path = os.path.join(monitor_dir, "stats-api-analysisd.csv")
        if not os.path.isfile(analysisd_stats_path):
            analysisd_stats_path = os.path.join(path, "stats-api-analysisd.csv")

        invsync_stats_path = os.path.join(path, "monitor", "stats-api-inventory-sync.csv")
        if not os.path.isfile(invsync_stats_path):
            invsync_stats_path = os.path.join(path, "stats-api-inventory-sync.csv")

        # remoted_module stats: prefer monitor/ subdir, fall back to root
        remoted_module_stats_path = os.path.join(monitor_dir, "stats-api-remoted-module.csv")
        if not os.path.isfile(remoted_module_stats_path):
            remoted_module_stats_path = os.path.join(path, "stats-api-remoted-module.csv")

        if os.path.isfile(bench_path):
            benches[label] = load_bench(bench_path)
        if os.path.isfile(disk_path):
            disk_dfs[label] = _keep_last_run(pd.read_csv(disk_path))
        if os.path.isfile(logs_path):
            try:
                logs[label] = pd.read_csv(logs_path)
            except Exception as exc:
                print(f"  warning: could not load {logs_path}: {exc}")
        if os.path.isfile(remoted_stats_path):
            try:
                remoted_dfs[label] = load_remoted_stats(remoted_stats_path)
            except Exception as exc:
                print(f"  warning: could not load {remoted_stats_path}: {exc}")
        if os.path.isfile(analysisd_stats_path):
            try:
                analysisd_dfs[label] = load_analysisd_stats(analysisd_stats_path)
            except Exception as exc:
                print(f"  warning: could not load {analysisd_stats_path}: {exc}")
        if os.path.isfile(invsync_stats_path):
            try:
                invsync_dfs[label] = load_invsync_stats(invsync_stats_path)
            except Exception as exc:
                print(f"  warning: could not load {invsync_stats_path}: {exc}")
        if os.path.isfile(remoted_module_stats_path):
            try:
                remoted_module_dfs[label] = load_remoted_module_stats(remoted_module_stats_path)
            except Exception as exc:
                print(f"  warning: could not load {remoted_module_stats_path}: {exc}")

        # Per-process CSVs: prefer monitor/ subdir, then root-level monitor.csv,
        # then auto-discover per-process CSVs in root.
        if os.path.isdir(monitor_dir):
            for fname in sorted(os.listdir(monitor_dir)):
                if not fname.endswith(".csv"):
                    continue
                if fname in STATS_CSV_NAMES:
                    continue
                fpath = os.path.join(monitor_dir, fname)
                proc_name = fname.removesuffix(".csv")
                key = f"{label}/{proc_name}" if len(result_dirs) > 1 else proc_name
                df = load_monitor(fpath)
                if len(df) == 0:
                    continue
                if proc_name in extra_proc_dfs:
                    extra_proc_dfs[proc_name][label] = df
                else:
                    monitors[key] = df
                    if "modulesd" in proc_name:
                        modulesd_dfs[label] = df
        elif os.path.isfile(monitor_path):
            monitors[label] = load_monitor(monitor_path)
            modulesd_dfs[label] = monitors[label]
        else:
            # Auto-discover per-process CSVs in root directory.
            for fname in sorted(os.listdir(path)):
                if not fname.endswith(".csv"):
                    continue
                if fname == "bench.csv" or fname in STATS_CSV_NAMES:
                    continue
                fpath = os.path.join(path, fname)
                proc_name = fname.removesuffix(".csv")
                key = f"{label}/{proc_name}" if len(result_dirs) > 1 else proc_name
                df = load_monitor(fpath)
                if len(df) == 0:
                    continue
                if proc_name in extra_proc_dfs:
                    extra_proc_dfs[proc_name][label] = df
                else:
                    monitors[key] = df
                    if "modulesd" in proc_name:
                        modulesd_dfs[label] = df

    has_extra_procs = any(extra_proc_dfs.values())
    if (not monitors and not benches and not disk_dfs and not remoted_dfs
            and not analysisd_dfs and not invsync_dfs and not remoted_module_dfs
            and not logs and not has_extra_procs):
        print("No data files found — nothing to generate.")
        return

    # Drop empty DataFrames (e.g. from processes that crashed before any sample).
    monitors = {k: v for k, v in monitors.items() if len(v) > 0}
    benches = {k: v for k, v in benches.items() if len(v) > 0}
    disk_dfs = {k: v for k, v in disk_dfs.items() if len(v) > 0}
    remoted_dfs = {k: v for k, v in remoted_dfs.items() if len(v) > 0}
    analysisd_dfs = {k: v for k, v in analysisd_dfs.items() if len(v) > 0}
    invsync_dfs = {k: v for k, v in invsync_dfs.items() if len(v) > 0}
    remoted_module_dfs = {k: v for k, v in remoted_module_dfs.items() if len(v) > 0}
    logs = {k: v for k, v in logs.items() if len(v) > 0}
    extra_proc_dfs = {
        name: {lbl: df for lbl, df in datasets.items() if len(df) > 0}
        for name, datasets in extra_proc_dfs.items()
    }
    has_extra_procs = any(extra_proc_dfs.values())

    if (not monitors and not benches and not disk_dfs and not remoted_dfs
            and not analysisd_dfs and not invsync_dfs and not remoted_module_dfs
            and not logs and not has_extra_procs):
        print("All CSV files are empty — nothing to generate.")
        return

    print(f"\nGenerating charts in {out_dir}/\n")

    # -- Monitor time-series: one chart per metric, overlaying all runs ------
    simple_extra_proc_dfs = {
        name: extra_proc_dfs.get(name, {})
        for name in SIMPLE_MONITOR_EXTRA_COMPONENTS
    }
    has_simple_extra_procs = any(simple_extra_proc_dfs.values())
    if monitors or has_simple_extra_procs:
        # For the simple per-metric charts, include wazuh-indexer and the
        # indexer-owned engine when available. For multi-result-dir runs the
        # key follows the same "{label}/{proc}" convention used by other
        # processes.
        monitors_with_simple_extras: dict[str, pd.DataFrame] = dict(monitors)
        for component, datasets in simple_extra_proc_dfs.items():
            for lbl, df in datasets.items():
                key = f"{lbl}/{component}" if len(result_dirs) > 1 else component
                monitors_with_simple_extras[key] = df

        for col, title_suffix, ylabel in MONITOR_METRICS:
            datasets = monitors_with_simple_extras
            title = f"Wazuh Manager — {title_suffix}"
            if col in _MEMORY_METRICS:
                datasets = {
                    key: df for key, df in datasets.items()
                    if key.split("/")[-1] not in _SCALE_BREAKING_COMPONENTS
                }
                title += " (manager processes)"
            out = os.path.join(out_dir, f"monitor_{col}.{fmt}")
            plot_timeseries(datasets, col, title, ylabel, out)

        if monitors:
            # manager-only: per-process lines + manager total (no indexer,
            # indexer engine, or dashboard).
            _plot_with_total(monitors, "cpu_pct", "CPU Usage (per process + total)",
                             "CPU %", os.path.join(out_dir, f"monitor_cpu_total.{fmt}"))
            _plot_with_total(monitors, "rss_mb", "RSS Memory (per process + total)",
                             "MB", os.path.join(out_dir, f"monitor_rss_total.{fmt}"))

            # combined: manager processes + optional all-in-one components +
            # single grand total. Keep the historical *_with_indexer filenames
            # because downstream docs and comparisons already reference them.
            total_extra_proc_dfs = {
                name: extra_proc_dfs.get(name, {})
                for name in TOTAL_MONITOR_EXTRA_COMPONENTS
                if extra_proc_dfs.get(name)
            }
            if total_extra_proc_dfs:
                _plot_with_total_and_extra_components(
                    monitors, total_extra_proc_dfs, "cpu_pct",
                    "CPU Usage — Manager + Indexer + Dashboard", "CPU %",
                    os.path.join(out_dir, f"monitor_cpu_total_with_indexer.{fmt}"))
                _plot_with_total_and_extra_components(
                    monitors, total_extra_proc_dfs, "rss_mb",
                    "RSS Memory — Manager + Indexer + Dashboard", "MB",
                    os.path.join(out_dir, f"monitor_rss_total_with_indexer.{fmt}"))

    # -- Disk-usage time series (from disk_usage.csv) ------------------------
    if disk_dfs:
        disk_cols: set[str] = set()
        for df in disk_dfs.values():
            disk_cols.update(c for c in df.columns if c.startswith("dir_") and c.endswith("_mb"))
        for col in sorted(disk_cols):
            pretty = col.removeprefix("dir_").removesuffix("_mb").replace("_", "-")
            out = os.path.join(out_dir, f"disk_{col}.{fmt}")
            plot_timeseries(
                disk_dfs, col,
                f"Disk Usage — {pretty}",
                "MB", out,
                y_min=0,
            )

        sorted_disk_cols = sorted(disk_cols)
        if sorted_disk_cols:
            if len(disk_dfs) == 1:
                _, df = next(iter(disk_dfs.items()))
                plot_multiline_timeseries(
                    df, sorted_disk_cols,
                    "Disk Usage - All Directories",
                    "MB",
                    os.path.join(out_dir, f"disk_all_dirs.{fmt}"),
                    y_min=0,
                )
            else:
                for label, df in disk_dfs.items():
                    safe_label = label.replace(" ", "_")
                    plot_multiline_timeseries(
                        df, sorted_disk_cols,
                        f"Disk Usage - All Directories ({label})",
                        "MB",
                        os.path.join(out_dir, f"disk_all_dirs_{safe_label}.{fmt}"),
                        y_min=0,
                    )

    # -- Bench time-series ---------------------------------------------------
    if benches:
        for col, title_suffix, ylabel in BENCH_METRICS:
            if not any(col in df.columns for df in benches.values()):
                continue
            out = os.path.join(out_dir, f"bench_{col}.{fmt}")
            plot_timeseries(
                benches, col,
                f"Wazuh Manager — {title_suffix}",
                ylabel, out,
            )

        # Sent vs accepted per run. Both cumulative, so the gap between the two
        # curves is what did not get a 200.
        if any("sessions_sent" in df.columns for df in benches.values()):
            plot_stacked_timeseries(
                benches,
                "sessions_sent", "sessions_ok",
                "Sessions sent (cumulative)", "Sessions answered 200 (cumulative)",
                "Count", "Count",
                "Sessions Sent vs Answered 200",
                os.path.join(out_dir, f"bench_sent_vs_ok.{fmt}"),
            )

    # -- Remoted API time-series --------------------------------------------
    if remoted_dfs:
        for col, title_suffix, ylabel in REMOTED_METRICS:
            if not any(col in df.columns for df in remoted_dfs.values()):
                continue
            out = os.path.join(out_dir, f"remoted_{col}.{fmt}")
            plot_timeseries(
                remoted_dfs,
                col,
                f"Wazuh Remoted API — {title_suffix}",
                ylabel,
                out,
            )

    # -- Analysisd API time-series ------------------------------------------
    if analysisd_dfs:
        for col, title_suffix, ylabel in ANALYSISD_METRICS:
            if not any(col in df.columns for df in analysisd_dfs.values()):
                continue
            out = os.path.join(out_dir, f"analysisd_{col}.{fmt}")
            plot_timeseries(
                analysisd_dfs,
                col,
                f"Analysisd — {title_suffix}",
                ylabel,
                out,
            )

        # Router queue (events): size + usage percent — stacked panels.
        # router.queue.size / router.queue.usage.percent are the event-count
        # view of the router's internal queue (see orchestrator.cpp), NOT bytes.
        if any("router_queue_size" in df.columns for df in analysisd_dfs.values()):
            plot_stacked_timeseries(
                analysisd_dfs,
                "router_queue_size", "router_queue_usage_percent",
                "Router Queue Size (events)", "Router Queue Size Usage %",
                "Events", "%",
                "Analysisd — Router Queue (events)",
                os.path.join(out_dir, f"analysisd_router_queue_events.{fmt}"),
            )

        # Router queue (bytes): size + usage percent — stacked panels.
        # router.queue.bytes.used / router.queue.bytes.usage.percent are the
        # byte-based view of the same queue, tracked independently of the
        # event-count view above.
        if any("router_queue_bytes_used" in df.columns for df in analysisd_dfs.values()):
            plot_stacked_timeseries(
                analysisd_dfs,
                "router_queue_bytes_used", "router_queue_bytes_usage_percent",
                "Router Queue Size (bytes)", "Router Queue Size Usage %",
                "Bytes", "%",
                "Analysisd — Router Queue (bytes)",
                os.path.join(out_dir, f"analysisd_router_queue_bytes.{fmt}"),
            )

        # Indexer queue: size + usage percent — stacked panels.
        # indexer.queue.size is only ever tracked in bytes (no event-count
        # variant exists for the indexer connector's egress queue).
        if any("indexer_queue_size" in df.columns for df in analysisd_dfs.values()):
            plot_stacked_timeseries(
                analysisd_dfs,
                "indexer_queue_size", "indexer_queue_usage_percent",
                "Indexer Queue Size (bytes)", "Indexer Queue Size Usage %",
                "Bytes", "%",
                "Analysisd — Indexer Queue (bytes)",
                os.path.join(out_dir, f"analysisd_indexer_queue.{fmt}"),
            )

        # -- Agent metadata cache -------------------------------------------
        # Per-metric overlay charts (one per run) for each cache metric.
        for col, title_suffix, ylabel in AGENT_CACHE_METRICS:
            if not any(col in df.columns for df in analysisd_dfs.values()):
                continue
            out = os.path.join(out_dir, f"analysisd_{col}.{fmt}")
            plot_timeseries(
                analysisd_dfs,
                col,
                f"Analysisd — {title_suffix}",
                ylabel,
                out,
            )

        # Combined cache overview: entries gauge (top) + cumulative counters
        # (bottom), one chart per run.
        if any(
            any(c in df.columns for c, _, _ in AGENT_CACHE_METRICS)
            for df in analysisd_dfs.values()
        ):
            for label, df in analysisd_dfs.items():
                safe_label = label.replace(" ", "_")
                _plot_agent_cache_overview(
                    df, label,
                    os.path.join(out_dir, f"analysisd_agent_cache_overview_{safe_label}.{fmt}"),
                )

    # -- inventory_sync_server -----------------------------------------------
    if invsync_dfs:
        for col, title_suffix, ylabel in INVSYNC_METRICS:
            if not any(col in df.columns for df in invsync_dfs.values()):
                continue
            out = os.path.join(out_dir, f"invsync_{col}.{fmt}")
            plot_timeseries(
                invsync_dfs,
                col,
                f"Inventory Sync Server \u2014 {title_suffix}",
                ylabel,
                out,
            )

        # Sharded ingest queue: total depth against the hottest single shard.
        # Two evenly-loaded shards and one hot shard look identical in the sum,
        # so the pair is what shows imbalance.
        if any("shard_depth_sum" in df.columns for df in invsync_dfs.values()):
            plot_stacked_timeseries(
                invsync_dfs,
                "shard_depth_sum", "shard_depth_max",
                "Queued items (all shards)", "Queued items (hottest shard)",
                "Items", "Items",
                "Inventory Sync Server \u2014 Sharded Ingest Queue",
                os.path.join(out_dir, f"invsync_shard_queue.{fmt}"),
            )

        # VD lane: how deep the queue gets vs how long a session spends in it.
        if any("vd_lane_depth" in df.columns for df in invsync_dfs.values()):
            plot_stacked_timeseries(
                invsync_dfs,
                "vd_lane_depth", "vd_lane_time_p99",
                "VD Lane Depth", "VD Lane Time p99",
                "Sessions", "microseconds",
                "Inventory Sync Server \u2014 Vulnerability Scan Lane",
                os.path.join(out_dir, f"invsync_vd_lane.{fmt}"),
            )

        # Backpressure: what was shed against what got through.
        if any("requests_503" in df.columns for df in invsync_dfs.values()):
            plot_stacked_timeseries(
                invsync_dfs,
                "requests_200", "requests_503",
                "Sessions Answered 200", "Sessions Shed (503)",
                "Count", "Count",
                "Inventory Sync Server \u2014 Accepted vs Shed",
                os.path.join(out_dir, f"invsync_accepted_vs_shed.{fmt}"),
            )

        # QoS: the reserve exists so control traffic keeps a lane while the data plane
        # saturates. Control staying served with data pinned at its cap is the whole point.
        if any("server_sessions_data" in df.columns for df in invsync_dfs.values()):
            plot_stacked_timeseries(
                invsync_dfs,
                "server_sessions_data", "server_sessions_control",
                "Data-class connections", "Control-class connections",
                "Connections", "Connections",
                "Inventory Sync Server \u2014 Connections by Route Class",
                os.path.join(out_dir, f"invsync_qos_sessions.{fmt}"),
            )

        # Budget pressure: bytes still admissible against what is resident in flight.
        if any("server_budget_available_bytes" in df.columns for df in invsync_dfs.values()):
            plot_stacked_timeseries(
                invsync_dfs,
                "server_budget_available_bytes", "server_budget_inflight_bytes",
                "Budget available", "Bytes in flight",
                "Bytes", "Bytes",
                "Inventory Sync Server \u2014 In-flight Byte Budget",
                os.path.join(out_dir, f"invsync_budget.{fmt}"),
            )

    # -- remoted_module (admin socket) ---------------------------------------
    if remoted_module_dfs:
        for col, title_suffix, ylabel in REMOTED_MODULE_METRICS:
            if not any(col in df.columns for df in remoted_module_dfs.values()):
                continue
            out = os.path.join(out_dir, f"remoted_module_{col}.{fmt}")
            plot_timeseries(
                remoted_module_dfs,
                col,
                f"Remoted Module \u2014 {title_suffix}",
                ylabel,
                out,
            )

        # The chart a saturation run is judged on: requests split into queued-and-will-run vs
        # honestly-shed, with vd_error as the failure line that must stay flat. One per run,
        # since the series only make sense read against each other.
        for label, df in remoted_module_dfs.items():
            if not any(col in df.columns for col in _SCANVD_FUNNEL_COLS):
                continue
            safe_label = label.replace(" ", "_")
            plot_multiline_timeseries(
                df, _SCANVD_FUNNEL_COLS,
                f"Remoted Module \u2014 VD Scan Funnel ({label})",
                "Count (cumulative)",
                os.path.join(out_dir, f"remoted_module_scanvd_funnel_{safe_label}.{fmt}"),
                y_min=0,
            )

        # WHY agents fail auth (pre-collapse causes) and WHY forwarded requests fail: same
        # read-together rationale as the scanvd funnel \u2014 one dominating line names the fix.
        for label, df in remoted_module_dfs.items():
            safe_label = label.replace(" ", "_")
            if any(col in df.columns for col in _AUTH_REJECT_FUNNEL_COLS):
                plot_multiline_timeseries(
                    df, _AUTH_REJECT_FUNNEL_COLS,
                    f"Remoted Module \u2014 Auth Rejections by Cause ({label})",
                    "Count (cumulative)",
                    os.path.join(out_dir, f"remoted_module_auth_reject_funnel_{safe_label}.{fmt}"),
                    y_min=0,
                )
            if any(col in df.columns for col in _ENROLL_OUTCOME_FUNNEL_COLS):
                plot_multiline_timeseries(
                    df, _ENROLL_OUTCOME_FUNNEL_COLS,
                    f"Remoted Module \u2014 Enrollment Outcomes ({label})",
                    "Count (cumulative)",
                    os.path.join(out_dir, f"remoted_module_enroll_outcome_funnel_{safe_label}.{fmt}"),
                    y_min=0,
                )
            if any(col in df.columns for col in _ENROLL_QUEUE_COLS):
                plot_multiline_timeseries(
                    df, _ENROLL_QUEUE_COLS,
                    f"Remoted Module \u2014 authd Queue Depth vs Capacity ({label})",
                    "Requests",
                    os.path.join(out_dir, f"remoted_module_enroll_authd_queue_{safe_label}.{fmt}"),
                    y_min=0,
                )
            if any(col in df.columns for col in _FWD_ERROR_FUNNEL_COLS):
                plot_multiline_timeseries(
                    df, _FWD_ERROR_FUNNEL_COLS,
                    f"Remoted Module \u2014 Downstream Failures by Cause ({label})",
                    "Count (cumulative)",
                    os.path.join(out_dir, f"remoted_module_fwd_error_funnel_{safe_label}.{fmt}"),
                    y_min=0,
                )
            # WHAT each forwarded endpoint answered its agents, one funnel per endpoint.
            for endpoint in _HTTP_RESPONSE_ENDPOINTS:
                cols = [f"http_{endpoint}_responses_{code}" for code in _HTTP_RESPONSE_CODES]
                if not any(col in df.columns for col in cols):
                    continue
                plot_multiline_timeseries(
                    df, cols,
                    f"Remoted Module \u2014 POST /{endpoint} Responses ({label})",
                    "Count (cumulative)",
                    os.path.join(out_dir, f"remoted_module_http_{endpoint}_responses_{safe_label}.{fmt}"),
                    y_min=0,
                )

        # Backpressure pairs, mirroring the inventory-sync transport charts: budget occupancy
        # (levels) and the deferred-work lane (occupancy vs its configured cap).
        if any("server_budget_available_bytes" in df.columns for df in remoted_module_dfs.values()):
            plot_stacked_timeseries(
                remoted_module_dfs,
                "server_budget_available_bytes", "server_budget_inflight_bytes",
                "Budget available", "Bytes in flight",
                "Bytes", "Bytes",
                "Remoted Module \u2014 In-flight Byte Budget",
                os.path.join(out_dir, f"remoted_module_budget.{fmt}"),
            )
        if any("forwarder_deferred_inflight" in df.columns for df in remoted_module_dfs.values()):
            plot_stacked_timeseries(
                remoted_module_dfs,
                "forwarder_deferred_inflight", "forwarder_deferred_capacity",
                "Deferred requests in flight", "Configured slot cap",
                "Requests", "Requests",
                "Remoted Module \u2014 Deferred-work Occupancy",
                os.path.join(out_dir, f"remoted_module_deferred.{fmt}"),
            )

    # -- Manager log events --------------------------------------------------
    # logs.csv counts what only the log can tell: throttled transport rejections (each line
    # carries the count for its 90 s window) and the failures with no metric behind them.
    for label, df in logs.items():
        safe_label = label.replace(" ", "_")
        _plot_log_events(
            df, label,
            os.path.join(out_dir, f"logs_events_{safe_label}.{fmt}"),
        )

    # -- Summary bar charts --------------------------------------------------
    if monitors:
        labels = list(monitors.keys())
        colors = [run_color(i) for i in range(len(labels))]

        # Peak RSS
        peak_rss = [df["rss_mb"].max() for df in monitors.values()]
        plot_bar(labels, peak_rss, colors,
                 "Peak RSS Memory", "MB",
                 os.path.join(out_dir, f"summary_peak_rss.{fmt}"))

        # Avg CPU
        avg_cpu = [round(df["cpu_pct"].mean(), 1) for df in monitors.values()]
        plot_bar(labels, avg_cpu, colors,
                 "Average CPU Usage", "CPU %",
                 os.path.join(out_dir, f"summary_avg_cpu.{fmt}"))

        # RSS growth (last - first)
        rss_growth = [
            round(df["rss_mb"].iloc[-1] - df["rss_mb"].iloc[0], 2)
            for df in monitors.values()
        ]
        plot_bar(labels, rss_growth, colors,
                 "RSS Memory Growth (end − start)", "MB",
                 os.path.join(out_dir, f"summary_rss_growth.{fmt}"))

        # Per-directory disk growth summary — all directories in one grouped bar chart.
        if disk_dfs:
            tracked_disk_cols: set[str] = set()
            for df in disk_dfs.values():
                tracked_disk_cols.update(c for c in df.columns
                                         if c.startswith("dir_") and c.endswith("_mb"))
            sorted_disk_cols = sorted(tracked_disk_cols)
            if sorted_disk_cols:
                _plot_grouped_disk_growth(
                    disk_dfs, sorted_disk_cols,
                    os.path.join(out_dir, f"summary_disk_growth.{fmt}"),
                )

    if benches:
        labels = list(benches.keys())
        colors = [run_color(i) for i in range(len(labels))]

        # bench.csv counters are CUMULATIVE, so a run's total is the last row --
        # summing the column would add every intermediate reading and inflate the
        # number by roughly the row count.
        def bench_total(df: pd.DataFrame, col: str) -> int:
            if col not in df.columns:
                return 0
            series = pd.to_numeric(df[col], errors="coerce").dropna()
            return int(series.iloc[-1]) if len(series) else 0

        for col, title, ylabel, only_if_nonzero in (
            ("sessions_sent",    "Total Sessions Sent",        "Sessions", False),
            ("sessions_ok",      "Total Sessions Answered 200", "Sessions", False),
            ("documents_sent",   "Total Documents Sent",       "Documents", False),
            ("sessions_503",     "Total Sessions Shed (503)",  "Sessions", True),
            ("sessions_500",     "Total Sessions Failed (500)", "Sessions", True),
            ("transport_errors", "Total Transport Errors",     "Errors", True),
            ("events_sent",      "Total Engine Events Sent",   "Events", True),
        ):
            totals = [bench_total(df, col) for df in benches.values()]
            if only_if_nonzero and not any(t > 0 for t in totals):
                continue
            if not any(t > 0 for t in totals):
                continue
            plot_bar(labels, totals, colors, title, ylabel,
                     os.path.join(out_dir, f"summary_{col}.{fmt}"))

    # -- Combined overlay: RSS + sessions on dual y-axis ---------------------
    # Keyed off modulesd_dfs, not monitors: in the per-process layout `monitors`
    # is keyed "<label>/<process>" while `benches` is keyed "<label>", so pairing
    # them by label never matched and this chart silently never appeared.
    if modulesd_dfs and benches:
        for label in modulesd_dfs:
            if label in benches and "sessions_ok" in benches[label].columns:
                out = os.path.join(
                    out_dir,
                    f"combined_rss_sessions_{label.replace(' ', '_')}.{fmt}",
                )
                _plot_combined(modulesd_dfs[label], benches[label], label, out)

    # -- Combined overlay: RSS + inventory_sync_server queue depth -----------
    # Overlays the module's own queue gauges with modulesd RSS to show
    # cause-effect: the queue grows → RSS grows.
    if modulesd_dfs and invsync_dfs:
        for label in modulesd_dfs:
            if label in invsync_dfs:
                df = invsync_dfs[label]
                if "shard_depth_sum" in df.columns and df["shard_depth_sum"].notna().any():
                    out = os.path.join(
                        out_dir,
                        f"combined_rss_queues_{label.replace(' ', '_')}.{fmt}",
                    )
                    _plot_rss_vs_queues(modulesd_dfs[label], df, label, out)


    print(f"\nDone. {len(os.listdir(out_dir))} chart(s) generated.\n")



def _plot_with_total(
    datasets: dict[str, pd.DataFrame],
    y_col: str,
    title: str,
    ylabel: str,
    out_path: str,
    figsize=(14, 6),
):
    """Plot each process as a line plus a bold 'Total' line summing all."""
    fig, ax = plt.subplots(figsize=figsize)

    # Build a total series by aligning on elapsed_s (integer seconds).
    # Each process df has elapsed_s as float; we truncate to int to align.
    # NOTE: do NOT use round() here — Python's banker's rounding causes .5
    # values like 599.5 and 600.5 to both map to 600, doubling contributions.
    totals: dict[int, float] = {}
    for idx, (label, df) in enumerate(datasets.items()):
        if y_col not in df.columns:
            continue
        ax.plot(
            df["elapsed_s"], df[y_col],
            label=label, color=run_color(idx),
            linewidth=1.2, alpha=0.7,
        )
        for t, v in zip(df["elapsed_s"], df[y_col]):
            t_r = int(float(t))
            totals[t_r] = totals.get(t_r, 0.0) + float(v)

    if totals:
        ts = sorted(totals.keys())
        vs = [totals[t] for t in ts]
        ax.plot(ts, vs, label="Total", color="#333333",
                linewidth=2.5, alpha=0.95, linestyle="--")

    ax.set_title(title, fontsize=14, fontweight="bold")
    ax.set_xlabel("Elapsed time (s)")
    ax.set_ylabel(ylabel)
    ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1), fontsize=9)
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


def _plot_with_total_and_extra_components(
    manager_datasets: dict[str, pd.DataFrame],
    extra_component_datasets: dict[str, dict[str, pd.DataFrame]],
    y_col: str,
    title: str,
    ylabel: str,
    out_path: str,
    figsize=(14, 7),
):
    """Manager process lines + extra component lines + grand total.

    For a single-result-dir run (manager keys have no "/") all manager
    processes are summed into one total, every available extra component is
    added on top, and a single "Total" line is drawn. For multi-result-dir
    runs each run gets its own total.
    """
    fig, ax = plt.subplots(figsize=figsize)

    def _run_of(key: str) -> str:
        """Return the run label part of a dataset key."""
        return key.split("/")[0] if "/" in key else ""

    def _component_df(
        component_datasets: dict[str, pd.DataFrame],
        run_label: str,
    ) -> pd.DataFrame | None:
        if run_label in component_datasets:
            return component_datasets[run_label]
        if not run_label and component_datasets:
            return next(iter(component_datasets.values()))
        return None

    # Accumulate per-run manager totals.
    run_labels = list(dict.fromkeys(_run_of(k) for k in manager_datasets))
    run_totals: dict[str, dict[int, float]] = {r: {} for r in run_labels}

    for idx, (label, df) in enumerate(manager_datasets.items()):
        if y_col not in df.columns:
            continue
        proc_name = label.split("/")[-1] if "/" in label else label
        run_label = _run_of(label)
        ax.plot(
            df["elapsed_s"], df[y_col],
            label=proc_name, color=run_color(idx),
            linewidth=1.0, alpha=0.5,
        )
        mt = run_totals[run_label]
        for t, v in zip(df["elapsed_s"], df[y_col]):
            t_r = int(float(t))
            mt[t_r] = mt.get(t_r, 0.0) + float(v)

    # For each run: add each extra component as its own line and compute one
    # grand total that includes every available extra component.
    for run_label in run_labels:
        mt = run_totals[run_label]
        suffix = f" ({run_label})" if len(run_labels) > 1 and run_label else ""
        grand: dict[int, float] = dict(mt)

        for comp_idx, (component, component_datasets) in enumerate(extra_component_datasets.items()):
            df = _component_df(component_datasets, run_label)
            if df is None or y_col not in df.columns:
                continue
            ax.plot(
                df["elapsed_s"], df[y_col],
                label=f"{component}{suffix}",
                color=run_color(len(manager_datasets) + comp_idx),
                linewidth=2.0, alpha=0.9, linestyle="-",
            )
            for t, v in zip(df["elapsed_s"], df[y_col]):
                t_r = int(float(t))
                grand[t_r] = grand.get(t_r, 0.0) + float(v)

        if grand:
            gts = sorted(grand.keys())
            gvs = [grand[t] for t in gts]
            ax.plot(gts, gvs,
                    label=f"Total{suffix}",
                    color="#000000", linewidth=2.5, alpha=0.95, linestyle="--")

    ax.set_title(title, fontsize=14, fontweight="bold")
    ax.set_xlabel("Elapsed time (s)")
    ax.set_ylabel(ylabel)
    ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1), fontsize=9)
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


def _plot_grouped_disk_growth(
    disk_dfs: dict[str, pd.DataFrame],
    columns: list[str],
    out_path: str,
    figsize=(12, 6),
):
    """All disk-directory growth values in a single grouped-bar chart.

    X-axis: directory names (columns prettified).
    Groups: one bar per run/label.
    """
    labels = list(disk_dfs.keys())
    n_labels = len(labels)
    n_cols = len(columns)
    bar_width = 0.7 / max(n_labels, 1)
    x = np.arange(n_cols)

    fig, ax = plt.subplots(figsize=figsize)
    for i, label in enumerate(labels):
        df = disk_dfs[label]
        values = []
        for col in columns:
            if col in df.columns and len(df) > 0:
                values.append(round(float(df[col].iloc[-1] - df[col].iloc[0]), 2))
            else:
                values.append(0.0)
        offset = (i - n_labels / 2 + 0.5) * bar_width
        bars = ax.bar(x + offset, values, bar_width,
                      label=label, color=run_color(i), edgecolor="white")
        for bar, val in zip(bars, values):
            if val != 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() * 1.01,
                        f"{val:.1f}", ha="center", va="bottom", fontsize=9)

    pretty_names = [c.removeprefix("dir_").removesuffix("_mb").replace("_", "-")
                    for c in columns]
    ax.set_xticks(x)
    ax.set_xticklabels(pretty_names, rotation=15, ha="right")
    ax.set_ylabel("MB")
    ax.set_title("Disk Growth (end − start) — All Directories", fontsize=14, fontweight="bold")
    ax.legend(loc="upper left", fontsize=9)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")



def _plot_rss_vs_queues(
    monitor_df: pd.DataFrame,
    invsync_df: pd.DataFrame,
    title: str,
    out_path: str,
):
    """Two stacked panels sharing X (elapsed_s):
      - Top:    modulesd RSS (MB), from the process monitor.
      - Bottom: queue depth inside inventory_sync_server -- the sharded ingest
                queue (max and total across shards) and the VD scan lane.

    This is the chart that shows the hotspot mechanism directly: when the shard
    depth climbs and the VD lane backs up, the RSS rise is readable at the same
    x position. shard_depth_max against shard_depth_sum also exposes imbalance,
    since one hot shard and evenly spread load look identical in the total.
    """
    fig, (ax1, ax2) = plt.subplots(
        2, 1,
        figsize=(14, 8),
        sharex=True,
        gridspec_kw={"height_ratios": [1, 1]},
    )

    # Panel 1 - RSS
    ax1.plot(monitor_df["elapsed_s"], monitor_df["rss_mb"],
             color=COLORS[3], linewidth=1.5, alpha=0.9, label="RSS (MB)")
    ax1.fill_between(monitor_df["elapsed_s"], monitor_df["rss_mb"],
                     alpha=0.15, color=COLORS[3])
    ax1.set_ylabel("RSS (MB)")
    ax1.set_title(f"Memory vs Inventory Sync Queue Depth - {title}",
                  fontsize=14, fontweight="bold")
    ax1.legend(loc="upper left", fontsize=9)
    ax1.grid(True, alpha=0.3)
    rss_max = monitor_df["rss_mb"].max()
    pad = max(rss_max * 0.05, 0.5)
    ax1.set_ylim(0, rss_max + pad)

    # Panel 2 - sharded ingest queue (left axis) + VD lane (right axis).
    x = invsync_df["elapsed_s"]
    depth_sum = pd.to_numeric(invsync_df["shard_depth_sum"], errors="coerce")
    depth_max = pd.to_numeric(invsync_df.get("shard_depth_max", pd.Series()), errors="coerce")
    vd_lane = pd.to_numeric(invsync_df.get("vd_lane_depth", pd.Series()), errors="coerce")

    ax2.plot(x, depth_sum, color=COLORS[2], linewidth=1.8,
             label="shard_depth_sum (all shards)")
    ax2.fill_between(x, depth_sum, alpha=0.15, color=COLORS[2])
    if depth_max.notna().any() and depth_max.max() > 0:
        ax2.plot(x, depth_max, color=COLORS[0], linewidth=1.2, alpha=0.8,
                 label="shard_depth_max (hottest shard)")
    ax2.set_xlabel("Elapsed time (s)")
    ax2.set_ylabel("Queued items")
    ax2.set_ylim(0, None)
    ax2.grid(True, alpha=0.3)
    ax2.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    if vd_lane.notna().any() and vd_lane.max() > 0:
        ax2b = ax2.twinx()
        ax2b.plot(x, vd_lane, color=COLORS[1], linewidth=1.2,
                  linestyle="--", alpha=0.8, label="vd_lane_depth")
        ax2b.set_ylabel("VD lane depth", color=COLORS[1])
        ax2b.tick_params(axis="y", labelcolor=COLORS[1])
        lines1, labels1 = ax2.get_legend_handles_labels()
        lines2, labels2 = ax2b.get_legend_handles_labels()
        ax2.legend(lines1 + lines2, labels1 + labels2,
                   loc="upper left", fontsize=9)
    else:
        ax2.legend(loc="upper left", fontsize=9)

    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


def _plot_combined(
    monitor_df: pd.DataFrame,
    bench_df: pd.DataFrame,
    title: str,
    out_path: str,
):
    """RSS memory and sessions completed/s in two stacked subplots sharing
    the X axis.

    Was previously a dual-Y overlay, but with per-second metrics that oscillate
    between 0 and ~30 the line was extremely noisy and overlapped with the
    RSS fill. Two panels + a rolling mean on sessions/s makes both signals
    readable independently.
    """
    fig, (ax1, ax2) = plt.subplots(
        2, 1,
        figsize=(14, 8),
        sharex=True,
        gridspec_kw={"height_ratios": [1, 1]},
    )

    # Panel 1 — RSS
    ax1.plot(monitor_df["elapsed_s"], monitor_df["rss_mb"],
             color=COLORS[3], linewidth=1.5, alpha=0.9, label="RSS (MB)")
    ax1.fill_between(monitor_df["elapsed_s"], monitor_df["rss_mb"],
                     alpha=0.15, color=COLORS[3])
    ax1.set_ylabel("RSS (MB)")
    ax1.set_title(f"Memory & Throughput — {title}",
                  fontsize=14, fontweight="bold")
    ax1.legend(loc="upper left", fontsize=9)
    ax1.grid(True, alpha=0.3)
    rss_max = monitor_df["rss_mb"].max()
    rss_min = monitor_df["rss_mb"].min()
    pad = max((rss_max - rss_min) * 0.1, 0.5)
    ax1.set_ylim(max(0, rss_min - pad), rss_max + pad)

    # Panel 2 — Sessions per second. bench.csv counts are cumulative, so the rate
    # is their first difference; plotting the counter itself here would just draw
    # a rising line and say nothing about throughput over time.
    cumulative = pd.to_numeric(bench_df["sessions_ok"], errors="coerce")
    raw = cumulative.diff().fillna(cumulative.iloc[0] if len(cumulative) else 0)
    raw = raw.clip(lower=0)  # a counter never decreases; guard against a reset
    smooth_window = 5
    avg  = _rolling(raw, smooth_window)

    ax2.plot(bench_df["elapsed_s"], raw,
             color=COLORS[2], linewidth=0.8, alpha=0.30,
             label="Sessions 200 / s (raw)")
    ax2.plot(bench_df["elapsed_s"], avg,
             color=COLORS[2], linewidth=1.8, alpha=1.0,
             label=f"Sessions 200 / s (rolling avg, w={smooth_window})")
    ax2.fill_between(bench_df["elapsed_s"], avg,
                     alpha=0.15, color=COLORS[2])
    ax2.set_xlabel("Elapsed time (s)")
    ax2.set_ylabel("Sessions 200 / s")
    ax2.legend(loc="upper right", fontsize=9)
    ax2.grid(True, alpha=0.3)
    ax2.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


def _plot_log_events(
    df: pd.DataFrame,
    label: str,
    out_path: str,
    figsize=(14, 6),
):
    """Cumulative timeline of the manager-log event counters (logs.csv).

    Only counters that actually fired in this run are drawn: the catalog covers every
    condition monitor.py knows how to recognise, and a normal run trips a handful of them, so
    plotting all of them would bury the signal under flat zero lines.

    Cumulative rather than per-second on purpose -- the underlying rows are per-second buckets
    of a THROTTLED log (one line every 90 s carrying its window's count), so the raw series is
    a sparse comb of spikes. The running total is what reads as "how much was shed by now".
    """
    counters = [c for c in df.columns if c not in ("timestamp", "elapsed_s")]
    active = [c for c in counters
              if pd.to_numeric(df[c], errors="coerce").fillna(0).sum() > 0]
    if not active:
        return

    fig, ax = plt.subplots(figsize=figsize)
    for idx, col in enumerate(active):
        series = pd.to_numeric(df[col], errors="coerce").fillna(0).cumsum()
        ax.plot(df["elapsed_s"], series,
                label=col.replace("_", "-"), color=run_color(idx),
                linewidth=1.4, alpha=0.85)

    ax.set_title(f"Manager Log Events — {label}", fontsize=14, fontweight="bold")
    ax.set_xlabel("Elapsed time (s)")
    ax.set_ylabel("Events (cumulative)")
    ax.set_ylim(bottom=0)
    ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1), fontsize=9)
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


def _plot_agent_cache_overview(
    df: pd.DataFrame,
    label: str,
    out_path: str,
):
    """Two stacked panels sharing X (elapsed_s) for the agent metadata cache:
      - Top:    entries — instantaneous number of cached agents (gauge).
      - Bottom: hits / insertions / updates / evictions — cumulative counters.

    The bottom panel makes the cache's effectiveness legible at a glance: hits
    climbing far faster than insertions/updates means most batches reuse a
    cached header (the win the cache exists for); evictions track TTL turnover.
    """
    counter_series = [
        ("agent_cache_hits",       "Hits",       COLORS[2]),
        ("agent_cache_insertions", "Insertions", COLORS[0]),
        ("agent_cache_updates",    "Updates",    COLORS[1]),
        ("agent_cache_evictions",  "Evictions",  COLORS[3]),
    ]
    has_entries = "agent_cache_entries" in df.columns and df["agent_cache_entries"].notna().any()
    has_counters = any(c in df.columns and df[c].notna().any() for c, _, _ in counter_series)
    if not has_entries and not has_counters:
        return

    # Derive the overall hit rate from the final cumulative values for the title.
    hit_rate_txt = ""
    if has_counters and {"agent_cache_hits", "agent_cache_insertions", "agent_cache_updates"}.issubset(df.columns):
        hits = float(pd.to_numeric(df["agent_cache_hits"], errors="coerce").fillna(0).iloc[-1])
        ins = float(pd.to_numeric(df["agent_cache_insertions"], errors="coerce").fillna(0).iloc[-1])
        upd = float(pd.to_numeric(df["agent_cache_updates"], errors="coerce").fillna(0).iloc[-1])
        lookups = hits + ins + upd
        if lookups > 0:
            hit_rate_txt = f"  —  hit rate {100.0 * hits / lookups:.1f}%"

    fig, (ax1, ax2) = plt.subplots(
        2, 1, figsize=(14, 8), sharex=True, gridspec_kw={"height_ratios": [1, 1]},
    )

    # Panel 1 — entries (gauge).
    if has_entries:
        ax1.plot(df["elapsed_s"], df["agent_cache_entries"],
                 color=COLORS[4], linewidth=1.6, alpha=0.9, label="Entries (current)")
        ax1.fill_between(df["elapsed_s"], df["agent_cache_entries"],
                         alpha=0.15, color=COLORS[4])
    ax1.set_ylabel("Entries")
    ax1.set_ylim(0, None)
    ax1.set_title(f"Analysisd — Agent Metadata Cache ({label}){hit_rate_txt}",
                  fontsize=14, fontweight="bold")
    ax1.legend(loc="upper left", fontsize=9)
    ax1.grid(True, alpha=0.3)

    # Panel 2 — cumulative counters.
    for col, name, color in counter_series:
        if col in df.columns and df[col].notna().any():
            ax2.plot(df["elapsed_s"], df[col],
                     color=color, linewidth=1.4, alpha=0.9, label=name)
    ax2.set_xlabel("Elapsed time (s)")
    ax2.set_ylabel("Count (cumulative)")
    ax2.set_ylim(0, None)
    ax2.legend(loc="upper left", fontsize=9)
    ax2.grid(True, alpha=0.3)
    ax2.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate comparison charts from Wazuh Manager benchmark results.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "-r", "--results", action="append", required=True,
        help="Results directory (optionally with label: path::label). "
             "Can be specified multiple times for comparison.",
    )
    p.add_argument(
        "-o", "--output", type=str, default="./charts",
        help="Output directory for charts (default: ./charts)",
    )
    p.add_argument(
        "--format", type=str, default="png", choices=["png", "svg", "pdf"],
        help="Chart output format (default: png)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    result_dirs = [parse_result_arg(r) for r in args.results]
    generate_charts(result_dirs, args.output, args.format)


if __name__ == "__main__":
    main()
