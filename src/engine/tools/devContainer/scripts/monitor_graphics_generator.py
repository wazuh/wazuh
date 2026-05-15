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

    for path, label in result_dirs:
        bench_path = os.path.join(path, "bench.csv")
        monitor_path = os.path.join(path, "monitor.csv")
        disk_path = os.path.join(path, "disk_usage.csv")
        if os.path.isfile(bench_path):
            benches[label] = load_bench(bench_path)
        if os.path.isfile(disk_path):
            disk_dfs[label] = load_monitor(disk_path)
        if os.path.isfile(monitor_path):
            monitors[label] = load_monitor(monitor_path)
        else:
            # Auto-discover per-process CSVs produced by the multi-process
            # monitor (e.g. wazuh-manager-analysisd.csv).
            for fname in sorted(os.listdir(path)):
                if not fname.endswith(".csv"):
                    continue
                if fname in ("bench.csv", "disk_usage.csv",
                            "invsync_queue_stats.csv", "invsync_session_stats.csv"):
                    continue
                fpath = os.path.join(path, fname)
                proc_name = fname.removesuffix(".csv")
                key = f"{label}/{proc_name}" if len(result_dirs) > 1 else proc_name
                monitors[key] = load_monitor(fpath)

    if not monitors and not benches and not disk_dfs:
        print("No data files found — nothing to generate.")
        return

    # Drop empty DataFrames (e.g. from processes that crashed before any sample).
    monitors = {k: v for k, v in monitors.items() if len(v) > 0}
    benches = {k: v for k, v in benches.items() if len(v) > 0}
    disk_dfs = {k: v for k, v in disk_dfs.items() if len(v) > 0}

    if not monitors and not benches and not disk_dfs:
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

        # Per-directory peak and growth summary bars from disk_usage.csv.
        if disk_dfs:
            tracked_disk_cols: set[str] = set()
            for df in disk_dfs.values():
                tracked_disk_cols.update(c for c in df.columns
                                         if c.startswith("dir_") and c.endswith("_mb"))
            disk_labels = list(disk_dfs.keys())
            disk_colors = [run_color(i) for i in range(len(disk_labels))]
            for col in sorted(tracked_disk_cols):
                pretty = col.removeprefix("dir_").removesuffix("_mb").replace("_", "-")
                peak = [round(df[col].max(), 2) if col in df.columns else 0.0
                        for df in disk_dfs.values()]
                plot_bar(disk_labels, peak, disk_colors,
                         f"Peak Disk Usage — {pretty}", "MB",
                         os.path.join(out_dir, f"summary_peak_{col}.{fmt}"))

                growth = []
                for df in disk_dfs.values():
                    if col in df.columns and len(df) > 0:
                        growth.append(round(df[col].iloc[-1] - df[col].iloc[0], 2))
                    else:
                        growth.append(0.0)
                plot_bar(disk_labels, growth, disk_colors,
                         f"Disk Growth — {pretty} (end − start)", "MB",
                         os.path.join(out_dir, f"summary_growth_{col}.{fmt}"))

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

    # -- InventorySync log charts (temporary) --------------------------------
    _generate_invsync_charts(result_dirs, out_dir, fmt)

    print(f"\nDone. {len(os.listdir(out_dir))} chart(s) generated.\n")


# ---------------------------------------------------------------------------
# InventorySync log charts (temporary — will be removed in the future)
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
) -> None:
    """Generate charts from invsync_queue_stats.csv and invsync_session_stats.csv.

    This function is temporary and will be removed in the future.
    """
    queue_dfs: dict[str, pd.DataFrame] = {}
    session_dfs: dict[str, pd.DataFrame] = {}

    for path, label in result_dirs:
        qpath = os.path.join(path, "invsync_queue_stats.csv")
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
