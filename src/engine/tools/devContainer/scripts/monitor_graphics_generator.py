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
    bench.csv     ->  timestamp, elapsed_s, messages_sent, sessions_started,
                      sessions_completed, sessions_failed, messages_dropped
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


def load_remoted_stats(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    if "elapsed_s" not in df.columns:
        df["elapsed_s"] = range(len(df))
    df = _keep_last_run(df)
    for col in df.columns:
        if col in (
            "timestamp", "query_error", "message", "data_name", "raw_response_json",
        ):
            continue
        df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


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

BENCH_METRICS = [
    ("messages_sent",       "Messages Sent / s",       "Count"),
    ("sessions_started",    "Sessions Started / s",     "Count"),
    ("sessions_completed",  "Sessions Completed / s",   "Count"),
    ("sessions_failed",     "Sessions Failed / s",      "Count"),
    ("messages_dropped",    "Messages Dropped / s",     "Count"),
]

REMOTED_METRICS = [
    ("queues_received_usage", "Remoted Queue Usage", "Usage"),
    (
        "messages_received_breakdown_discarded",
        "Remoted Messages Received Discarded",
        "Count",
    ),
    (
        "messages_received_breakdown_event",
        "Remoted Messages Received Event",
        "Count",
    ),
    (
        "messages_sent_breakdown_discarded",
        "Remoted Messages Sent Discarded",
        "Count",
    ),
    ("tcp_sessions", "Remoted TCP Sessions", "Count"),
]


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
    logs: dict[str, pd.DataFrame] = {}
    modulesd_dfs: dict[str, pd.DataFrame] = {}

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

        # Per-process CSVs: prefer monitor/ subdir, then root-level monitor.csv,
        # then auto-discover per-process CSVs in root.
        if os.path.isdir(monitor_dir):
            for fname in sorted(os.listdir(monitor_dir)):
                if not fname.endswith(".csv"):
                    continue
                if fname in ("disk_usage.csv", "logs.csv",
                             "invsync_queue_stats.csv", "invsync_session_stats.csv",
                             "stats-api-remoted.csv"):
                    continue
                fpath = os.path.join(monitor_dir, fname)
                proc_name = fname.removesuffix(".csv")
                key = f"{label}/{proc_name}" if len(result_dirs) > 1 else proc_name
                df = load_monitor(fpath)
                if len(df) > 0:
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
                if fname in ("bench.csv", "disk_usage.csv", "logs.csv",
                             "invsync_queue_stats.csv", "invsync_session_stats.csv",
                             "stats-api-remoted.csv"):
                    continue
                fpath = os.path.join(path, fname)
                proc_name = fname.removesuffix(".csv")
                key = f"{label}/{proc_name}" if len(result_dirs) > 1 else proc_name
                df = load_monitor(fpath)
                if len(df) > 0:
                    monitors[key] = df
                if "modulesd" in proc_name:
                    modulesd_dfs[label] = df

    if not monitors and not benches and not disk_dfs and not remoted_dfs:
        print("No data files found — nothing to generate.")
        return

    # Drop empty DataFrames (e.g. from processes that crashed before any sample).
    monitors = {k: v for k, v in monitors.items() if len(v) > 0}
    benches = {k: v for k, v in benches.items() if len(v) > 0}
    disk_dfs = {k: v for k, v in disk_dfs.items() if len(v) > 0}
    remoted_dfs = {k: v for k, v in remoted_dfs.items() if len(v) > 0}

    if not monitors and not benches and not disk_dfs and not remoted_dfs:
        print("All CSV files are empty — nothing to generate.")
        return

    print(f"\nGenerating charts in {out_dir}/\n")

    # -- Monitor time-series: one chart per metric, overlaying all runs ------
    if monitors:
        for col, title_suffix, ylabel in MONITOR_METRICS:
            out = os.path.join(out_dir, f"monitor_{col}.{fmt}")
            plot_timeseries(
                monitors, col,
                f"Wazuh Manager — {title_suffix}",
                ylabel, out,
            )

        # Combined CPU and RSS charts with per-process lines + total sum.
        _plot_with_total(monitors, "cpu_pct", "CPU Usage (per process + total)",
                         "CPU %", os.path.join(out_dir, f"monitor_cpu_total.{fmt}"))
        _plot_with_total(monitors, "rss_mb", "RSS Memory (per process + total)",
                         "MB", os.path.join(out_dir, f"monitor_rss_total.{fmt}"))

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

    # -- Bench time-series ---------------------------------------------------
    if benches:
        for col, title_suffix, ylabel in BENCH_METRICS:
            out = os.path.join(out_dir, f"bench_{col}.{fmt}")
            plot_timeseries(
                benches, col,
                f"Wazuh Manager — {title_suffix}",
                ylabel, out,
            )

        # Sent vs completed per run — stacked subplots, smoothed sessions/s
        plot_stacked_timeseries(
            benches,
            "messages_sent", "sessions_completed",
            "Messages sent / s", "Sessions completed / s",
            "Messages / s", "Sessions / s",
            "Messages Sent vs Sessions Completed",
            os.path.join(out_dir, f"bench_sent_vs_completed.{fmt}"),
            smooth_b_window=5,
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

        # Total sessions completed
        total_completed = [
            int(df["sessions_completed"].sum()) for df in benches.values()
        ]
        plot_bar(labels, total_completed, colors,
                 "Total Sessions Completed", "Sessions",
                 os.path.join(out_dir, f"summary_sessions_completed.{fmt}"))

        # Total messages sent
        total_sent = [int(df["messages_sent"].sum()) for df in benches.values()]
        plot_bar(labels, total_sent, colors,
                 "Total Messages Sent", "Messages",
                 os.path.join(out_dir, f"summary_messages_sent.{fmt}"))

        # Total dropped
        total_dropped = [
            int(df["messages_dropped"].sum()) for df in benches.values()
        ]
        if any(d > 0 for d in total_dropped):
            plot_bar(labels, total_dropped, colors,
                     "Total Messages Dropped", "Messages",
                     os.path.join(out_dir, f"summary_messages_dropped.{fmt}"))

    # -- Combined overlay: RSS + sessions on dual y-axis ---------------------
    if monitors and benches:
        for label in monitors:
            if label in benches:
                out = os.path.join(
                    out_dir,
                    f"combined_rss_sessions_{label.replace(' ', '_')}.{fmt}",
                )
                _plot_combined(monitors[label], benches[label], label, out)

    # -- Combined overlay: RSS + manager-side queue depth --------------------
    # Reads queue stats from logs.csv (workers_q, indexer_q, sessions) and
    # overlays them with RSS to show cause-effect: queue grows → RSS grows.
    if modulesd_dfs and logs:
        for label in modulesd_dfs:
            if label in logs:
                df = logs[label]
                if "workers_q" in df.columns and df["workers_q"].notna().any():
                    out = os.path.join(
                        out_dir,
                        f"combined_rss_queues_{label.replace(' ', '_')}.{fmt}",
                    )
                    _plot_rss_vs_queues(modulesd_dfs[label], df, label, out)

    # -- InventorySync log charts --------------------------------------------
    _generate_invsync_charts(result_dirs, out_dir, fmt, modulesd_dfs)

    print(f"\nDone. {len(os.listdir(out_dir))} chart(s) generated.\n")


# ---------------------------------------------------------------------------
# InventorySync log charts
# ---------------------------------------------------------------------------
INVSYNC_QUEUE_METRICS = [
    ("workers_q",         "Workers Queue Depth",     "Count"),
    ("indexer_q",         "Indexer Queue Depth",      "Count"),
    ("sessions",          "Active Sessions",          "Count"),
    ("blocked_agents",    "Blocked Agents",           "Count"),
    ("active_vdfirst",    "Active VD-First",          "Count"),
    ("indexer_bulk_bytes", "Indexer Bulk Bytes",       "Bytes"),
    ("indexer_notify",    "Indexer Notify Count",      "Count"),
    ("indexer_delbyq",    "Indexer Delete-by-Query",   "Count"),
    ("rocksdb_dir_bytes", "RocksDB Directory Size",    "Bytes"),
]

INVSYNC_SESSION_TIMING = [
    ("timing_ms_start_to_processing", "Start → Processing", "ms"),
    ("timing_ms_start_to_end",        "Start → End",        "ms"),
]


def _generate_invsync_charts(
    result_dirs: list[tuple[str, str]],
    out_dir: str,
    fmt: str,
    modulesd_dfs: dict[str, pd.DataFrame] | None = None,
) -> None:
    """Generate charts from invsync_queue_stats.csv and invsync_session_stats.csv."""
    queue_dfs: dict[str, pd.DataFrame] = {}
    session_dfs: dict[str, pd.DataFrame] = {}

    for path, label in result_dirs:
        monitor_dir = os.path.join(path, "monitor")
        # Prefer monitor/ subdir, fall back to root
        qpath = os.path.join(monitor_dir, "invsync_queue_stats.csv")
        if not os.path.isfile(qpath):
            qpath = os.path.join(path, "invsync_queue_stats.csv")
        spath = os.path.join(monitor_dir, "invsync_session_stats.csv")
        if not os.path.isfile(spath):
            spath = os.path.join(path, "invsync_session_stats.csv")
        if os.path.isfile(qpath):
            df = pd.read_csv(qpath)
            if len(df) > 0:
                # Add a sequential elapsed index (rows are ~0.5s apart)
                df["elapsed_s"] = [i * 0.5 for i in range(len(df))]
                # Coerce numeric columns
                for c in df.columns:
                    if c not in ("timestamp",):
                        df[c] = pd.to_numeric(df[c], errors="coerce")
                queue_dfs[label] = df
        if os.path.isfile(spath):
            df = pd.read_csv(spath)
            if len(df) > 0:
                for c in df.columns:
                    if c not in ("timestamp", "agent", "module", "sessionId", "reason"):
                        df[c] = pd.to_numeric(df[c], errors="coerce")
                session_dfs[label] = df

    if not queue_dfs and not session_dfs:
        return

    # -- Queue stats time-series ---------------------------------------------
    for col, title_suffix, ylabel in INVSYNC_QUEUE_METRICS:
        if not any(col in df.columns for df in queue_dfs.values()):
            continue
        out = os.path.join(out_dir, f"invsync_queue_{col}.{fmt}")
        plot_timeseries(
            queue_dfs, col,
            f"InventorySync — {title_suffix}",
            ylabel, out,
        )

    # -- Session stats: timing bar charts per module -------------------------
    for label, df in session_dfs.items():
        if "module" not in df.columns:
            continue
        for col, title_suffix, ylabel in INVSYNC_SESSION_TIMING:
            if col not in df.columns:
                continue
            # Group by module, compute mean
            grouped = df.groupby("module")[col].mean()
            if grouped.empty:
                continue
            modules = list(grouped.index)
            values = [round(v, 1) for v in grouped.values]
            colors = [run_color(i) for i in range(len(modules))]
            suffix = f" ({label})" if len(session_dfs) > 1 else ""
            out = os.path.join(out_dir,
                               f"invsync_session_{col}_{label.replace(' ', '_')}.{fmt}")
            plot_bar(
                modules, values, colors,
                f"InventorySync Session — Avg {title_suffix}{suffix}",
                ylabel, out,
            )

        # Session lifecycle Gantt: per-agent timeline showing when each
        # session was Start → Processing → End. Lets you eyeball whether
        # sessions chain back-to-back (the design we want from the sender)
        # vs sitting idle, AND whether time is being spent on the agent→
        # manager link (start→processing) or inside the manager
        # (processing→end).
        if {"timing_ms_start_to_end", "timing_ms_start_to_processing",
            "agent", "timestamp"}.issubset(df.columns):
            _plot_session_lifecycle(
                df, label,
                os.path.join(out_dir,
                             f"invsync_session_lifecycle_{label.replace(' ', '_')}.{fmt}"),
            )
            _plot_session_gaps(
                df, label,
                os.path.join(out_dir,
                             f"invsync_session_gaps_{label.replace(' ', '_')}.{fmt}"),
            )

        # Sessions completed per module
        if "reason" in df.columns:
            completed = df[df["reason"] == "completed"]
            if not completed.empty and "module" in completed.columns:
                counts = completed.groupby("module").size()
                modules = list(counts.index)
                values = list(counts.values)
                colors = [run_color(i) for i in range(len(modules))]
                suffix = f" ({label})" if len(session_dfs) > 1 else ""
                out = os.path.join(out_dir,
                                   f"invsync_session_completed_{label.replace(' ', '_')}.{fmt}")
                plot_bar(
                    modules, values, colors,
                    f"InventorySync — Sessions Completed by Module{suffix}",
                    "Count", out,
                )

    # -- Combined: sessions + modulesd RSS + rocksdb dir size ----------------
    if modulesd_dfs and queue_dfs:
        for label in queue_dfs:
            if label in (modulesd_dfs or {}):
                out = os.path.join(
                    out_dir,
                    f"invsync_combined_sessions_rss_rocksdb_{label.replace(' ', '_')}.{fmt}",
                )
                _plot_sessions_rss_rocksdb(
                    queue_dfs[label], modulesd_dfs[label], label, out)


def _session_timeline_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Reconstruct per-session (start, processing, end) wall-clock instants
    from invsync_session_stats rows. Each row records the END of a session
    plus durations relative to its start, so the start/processing instants
    are derived by subtraction.

    Returns a copy of df with extra columns:
      ts_end, ts_start, ts_processing   (datetime)
      start_s, proc_s, end_s            (float seconds since the earliest
                                         session start in the frame)
    Rows without numeric timings are dropped.
    """
    out = df.copy()
    out["timing_ms_start_to_end"] = pd.to_numeric(
        out.get("timing_ms_start_to_end"), errors="coerce")
    out["timing_ms_start_to_processing"] = pd.to_numeric(
        out.get("timing_ms_start_to_processing"), errors="coerce")
    out = out.dropna(subset=["timing_ms_start_to_end",
                             "timing_ms_start_to_processing"])
    if out.empty:
        return out

    # invsync_session_stats.csv timestamps look like "2026/05/21 03:27:59"
    # (1-second granularity). dur/proc are millisecond precision so the
    # derived start/processing instants are accurate even though the
    # recorded end is rounded to the second.
    out["ts_end"] = pd.to_datetime(out["timestamp"], errors="coerce")
    out = out.dropna(subset=["ts_end"])
    if out.empty:
        return out

    out["ts_start"] = out["ts_end"] - pd.to_timedelta(
        out["timing_ms_start_to_end"], unit="ms")
    out["ts_processing"] = out["ts_start"] + pd.to_timedelta(
        out["timing_ms_start_to_processing"], unit="ms")

    t0 = out["ts_start"].min()
    out["start_s"] = (out["ts_start"]      - t0).dt.total_seconds()
    out["proc_s"]  = (out["ts_processing"] - t0).dt.total_seconds()
    out["end_s"]   = (out["ts_end"]        - t0).dt.total_seconds()
    return out


def _plot_session_lifecycle(
    df: pd.DataFrame,
    label: str,
    out_path: str,
):
    """Gantt-style chart of every session in the run, one lane per agent.

    Each session draws two stacked segments:
      - light segment: Start → Processing (agent→manager latency, manager
        acceptance + StartAck, mostly network + queue admission)
      - dark segment:  Processing → End (manager bulk-index + EndAck latency)

    The gaps between bars on the same lane are the idle windows between
    iterations of an agent — i.e. sender-side reconnect overhead +
    handshake. If you see consistent narrow gaps, sessions chain
    back-to-back; if you see large white blocks, the sender is sitting
    idle and you should look at the reconnect path in agent_loop.
    """
    frame = _session_timeline_frame(df)
    if frame.empty or "agent" not in frame.columns:
        return

    # One lane per agent. Sort by first-session time so the lanes are
    # ordered the same way they started.
    lane_order: list[str] = (
        frame.sort_values("start_s")["agent"].drop_duplicates().tolist()
    )
    lane_y = {a: i for i, a in enumerate(lane_order)}

    height = max(3.5, 0.55 * len(lane_order) + 2.0)
    fig, ax = plt.subplots(figsize=(14, height))

    # Color segments via the existing palette: start→processing in COLORS[0]
    # (lighter accent), processing→end in COLORS[2] (where the time is
    # actually spent in practice).
    for _, row in frame.iterrows():
        y = lane_y[row["agent"]]
        pre  = max(0.0, row["proc_s"] - row["start_s"])
        post = max(0.0, row["end_s"]  - row["proc_s"])
        if pre > 0:
            ax.barh(y, pre, left=row["start_s"], height=0.7,
                    color=COLORS[0], alpha=0.55,
                    edgecolor="white", linewidth=0.4)
        if post > 0:
            ax.barh(y, post, left=row["proc_s"], height=0.7,
                    color=COLORS[2], alpha=0.85,
                    edgecolor="white", linewidth=0.4)

    ax.set_yticks(list(lane_y.values()))
    ax.set_yticklabels(lane_order, fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel("Elapsed time (s) — t0 = first session start")
    ax.set_title(f"InventorySync — Session Lifecycle ({label})",
                 fontsize=14, fontweight="bold")
    ax.grid(True, axis="x", alpha=0.3)
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    # Custom legend so the colors map to phases regardless of which agent
    # we drew first.
    from matplotlib.patches import Patch
    legend_handles = [
        Patch(color=COLORS[0], alpha=0.55, label="Start → Processing"),
        Patch(color=COLORS[2], alpha=0.85, label="Processing → End"),
    ]
    ax.legend(handles=legend_handles, loc="upper right", fontsize=9)

    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


def _plot_session_gaps(
    df: pd.DataFrame,
    label: str,
    out_path: str,
):
    """Histogram + per-agent strip of idle gaps between consecutive sessions.

    Used to answer "are sessions of an agent running back-to-back?". A
    narrow histogram clustered near 0 means yes; a long tail or multimodal
    distribution means the sender (or manager) is inserting unexpected
    waits between iterations.
    """
    frame = _session_timeline_frame(df)
    if frame.empty or "agent" not in frame.columns:
        return

    # Per-agent gaps: gap = next.start_s − this.end_s
    gap_records: list[tuple[str, float]] = []
    for agent_id, sub in frame.groupby("agent"):
        sub = sub.sort_values("start_s")
        prev_end = sub["end_s"].shift(1)
        gaps = (sub["start_s"] - prev_end).dropna()
        for g in gaps:
            gap_records.append((agent_id, float(g)))

    if not gap_records:
        return

    agents = sorted({a for a, _ in gap_records})
    agent_lane = {a: i for i, a in enumerate(agents)}
    values = [g for _, g in gap_records]

    fig, (ax1, ax2) = plt.subplots(
        2, 1, figsize=(12, max(5, 0.4 * len(agents) + 4)),
        gridspec_kw={"height_ratios": [1, max(1, len(agents) / 4)]},
    )

    # Top: histogram of all gaps.
    ax1.hist(values, bins=20, color=COLORS[2], edgecolor="white", alpha=0.85)
    ax1.set_title(f"Inter-session idle gaps ({label})",
                  fontsize=13, fontweight="bold")
    ax1.set_xlabel("Gap between end-of-session N and start-of-session N+1 (s)")
    ax1.set_ylabel("Count")
    ax1.grid(True, alpha=0.3)
    median = float(np.median(values))
    ax1.axvline(median, color=COLORS[3], linestyle="--", linewidth=1.4,
                label=f"median = {median:.2f} s")
    ax1.legend(loc="upper right", fontsize=9)

    # Bottom: strip plot per agent (each dot = one gap).
    for agent_id, g in gap_records:
        ax2.scatter(g, agent_lane[agent_id], color=COLORS[0], alpha=0.8, s=30)
    ax2.set_yticks(list(agent_lane.values()))
    ax2.set_yticklabels(agents, fontsize=8)
    ax2.invert_yaxis()
    ax2.set_xlabel("Gap (s)")
    ax2.grid(True, axis="x", alpha=0.3)

    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


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


def _plot_sessions_rss_rocksdb(
    queue_df: pd.DataFrame,
    modulesd_df: pd.DataFrame,
    title: str,
    out_path: str,
):
    """Three stacked panels sharing X (elapsed_s):
      - Top:    Active sessions (from invsync_queue_stats).
      - Middle: RSS of modulesd (MB).
      - Bottom: RocksDB directory size (converted to MB).
    """
    fig, (ax1, ax2, ax3) = plt.subplots(
        3, 1,
        figsize=(14, 10),
        sharex=True,
        gridspec_kw={"height_ratios": [1, 1, 1]},
    )

    # Panel 1 — Sessions
    if "sessions" in queue_df.columns:
        ax1.plot(queue_df["elapsed_s"], queue_df["sessions"],
                 color=COLORS[0], linewidth=1.5, alpha=0.9, label="Active Sessions")
        ax1.fill_between(queue_df["elapsed_s"], queue_df["sessions"],
                         alpha=0.15, color=COLORS[0])
    ax1.set_ylabel("Sessions")
    ax1.set_ylim(0, None)
    ax1.set_title(f"InventorySync — Sessions + RSS + RocksDB ({title})",
                  fontsize=14, fontweight="bold")
    ax1.legend(loc="upper left", fontsize=9)
    ax1.grid(True, alpha=0.3)

    # Panel 2 — RSS (modulesd)
    if "rss_mb" in modulesd_df.columns:
        ax2.plot(modulesd_df["elapsed_s"], modulesd_df["rss_mb"],
                 color=COLORS[3], linewidth=1.5, alpha=0.9, label="RSS modulesd (MB)")
        ax2.fill_between(modulesd_df["elapsed_s"], modulesd_df["rss_mb"],
                         alpha=0.15, color=COLORS[3])
    ax2.set_ylabel("MB")
    ax2.set_ylim(0, None)
    ax2.legend(loc="upper left", fontsize=9)
    ax2.grid(True, alpha=0.3)

    # Panel 3 — RocksDB dir size (bytes -> MB)
    if "rocksdb_dir_bytes" in queue_df.columns:
        rocksdb_mb = queue_df["rocksdb_dir_bytes"] / (1024 * 1024)
        ax3.plot(queue_df["elapsed_s"], rocksdb_mb,
                 color=COLORS[2], linewidth=1.5, alpha=0.9, label="RocksDB dir (MB)")
        ax3.fill_between(queue_df["elapsed_s"], rocksdb_mb,
                         alpha=0.15, color=COLORS[2])
    ax3.set_ylabel("MB")
    ax3.set_ylim(0, None)
    ax3.set_xlabel("Elapsed time (s)")
    ax3.legend(loc="upper left", fontsize=9)
    ax3.grid(True, alpha=0.3)
    ax3.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


def _plot_rss_vs_queues(
    monitor_df: pd.DataFrame,
    logs_df: pd.DataFrame,
    title: str,
    out_path: str,
):
    """Two stacked panels sharing X (elapsed_s):
      - Top:    RSS (MB) from the engine monitor.
      - Bottom: workers_q + indexer_q + sessions from logs.csv (queue stats
                emitted by the manager).

    This is the chart that visualises the hotspot mechanism directly: when
    workers_q climbs and sessions stay near the cap, you can read the RSS
    rise off the top panel for the same x position.
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
    ax1.set_title(f"Memory vs Manager Queue Depth — {title}",
                  fontsize=14, fontweight="bold")
    ax1.legend(loc="upper left", fontsize=9)
    ax1.grid(True, alpha=0.3)
    rss_max = monitor_df["rss_mb"].max()
    pad = max(rss_max * 0.05, 0.5)
    ax1.set_ylim(0, rss_max + pad)

    # Panel 2 — workers_q (left axis) + sessions (right axis).
    x = logs_df["elapsed_s"]
    workers = pd.to_numeric(logs_df["workers_q"], errors="coerce")
    indexer = pd.to_numeric(logs_df.get("indexer_q", pd.Series()), errors="coerce")
    sessions = pd.to_numeric(logs_df.get("sessions", pd.Series()), errors="coerce")

    ax2.plot(x, workers, color=COLORS[2], linewidth=1.8,
             label="workers_q (m_workersQueue depth)")
    ax2.fill_between(x, workers, alpha=0.15, color=COLORS[2])
    if indexer.notna().any() and indexer.max() > 0:
        ax2.plot(x, indexer, color=COLORS[0], linewidth=1.2, alpha=0.8,
                 label="indexer_q (m_indexerQueue depth)")
    ax2.set_xlabel("Elapsed time (s)")
    ax2.set_ylabel("Queue depth (messages)")
    ax2.set_ylim(0, None)
    ax2.grid(True, alpha=0.3)
    ax2.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    if sessions.notna().any():
        ax2b = ax2.twinx()
        ax2b.plot(x, sessions, color=COLORS[1], linewidth=1.2,
                  linestyle="--", alpha=0.8, label="sessions (active)")
        ax2b.set_ylabel("Active sessions", color=COLORS[1])
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

    # Panel 2 — Sessions completed per second, with 5s rolling mean overlay.
    raw  = bench_df["sessions_completed"]
    smooth_window = 5
    avg  = _rolling(raw, smooth_window)

    ax2.plot(bench_df["elapsed_s"], raw,
             color=COLORS[2], linewidth=0.8, alpha=0.30,
             label="Sessions completed / s (raw)")
    ax2.plot(bench_df["elapsed_s"], avg,
             color=COLORS[2], linewidth=1.8, alpha=1.0,
             label=f"Sessions completed / s (rolling avg, w={smooth_window})")
    ax2.fill_between(bench_df["elapsed_s"], avg,
                     alpha=0.15, color=COLORS[2])
    ax2.set_xlabel("Elapsed time (s)")
    ax2.set_ylabel("Sessions completed / s")
    ax2.legend(loc="upper right", fontsize=9)
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
