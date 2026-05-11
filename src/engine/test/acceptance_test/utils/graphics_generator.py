#!/usr/bin/env python3
from __future__ import annotations
"""
graphics_generator.py – Benchmark results visualizer.

Reads the ``results/`` directory produced by ``acceptance_test.sh`` and
generates comparison charts across different orchestrator-thread counts.

Expected files inside the results directory (per thread count N):
    monitor-NT.csv   →  timestamp, cpu_pct, rss_mb, vms_mb, fds,
                        read_ops, write_ops, read_bytes, write_bytes, disk_pct
    bench-NT.csv     →  timestamp, sent, processed

Usage:
    python3 graphics_generator.py -r ./results -o ./charts
    python3 graphics_generator.py -r ./results -o ./charts --format svg
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


def thread_color(idx: int) -> str:
    return COLORS[idx % len(COLORS)]


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def discover_thread_counts(results_dir: str) -> list[int]:
    """Return sorted list of thread counts found in results_dir."""
    pattern = re.compile(r"^monitor-(\d+)T\.csv$")
    counts = set()
    for name in os.listdir(results_dir):
        m = pattern.match(name)
        if m:
            counts.add(int(m.group(1)))
    # Also check bench files in case a monitor CSV is missing
    pattern_b = re.compile(r"^bench-(\d+)T\.csv$")
    for name in os.listdir(results_dir):
        m = pattern_b.match(name)
        if m:
            counts.add(int(m.group(1)))
    return sorted(counts)


def load_monitor(results_dir: str, threads: int) -> pd.DataFrame:
    path = os.path.join(results_dir, f"monitor-{threads}T.csv")
    df = pd.read_csv(path, parse_dates=["timestamp"])
    df["elapsed_s"] = range(len(df))
    return df


def load_bench(results_dir: str, threads: int) -> pd.DataFrame:
    path = os.path.join(results_dir, f"bench-{threads}T.csv")
    df = pd.read_csv(path, parse_dates=["timestamp"])
    df["elapsed_s"] = range(len(df))
    return df


def load_bench_full_timeline(results_dir: str, threads: int) -> pd.DataFrame | None:
    """Concatenate warmup + grace-gap + measured bench CSVs.

    Returns a single DataFrame that covers the entire benchmark timeline,
    filling the grace period between warmup and measured with zero rows so
    the bench x-axis matches the monitor's full duration.
    Returns None if both files are missing.
    """
    warmup_path = os.path.join(results_dir, f"bench-{threads}T-warmup.csv")
    measured_path = os.path.join(results_dir, f"bench-{threads}T.csv")

    parts: list[pd.DataFrame] = []
    if os.path.isfile(warmup_path):
        parts.append(pd.read_csv(warmup_path, parse_dates=["timestamp"]))
    if os.path.isfile(measured_path):
        parts.append(pd.read_csv(measured_path, parse_dates=["timestamp"]))
    if not parts:
        return None

    if len(parts) == 2:
        warmup, measured = parts
        gap_start = warmup["timestamp"].max() + pd.Timedelta(seconds=1)
        gap_end = measured["timestamp"].min() - pd.Timedelta(seconds=1)
        if gap_end > gap_start:
            gap_ts = pd.date_range(gap_start, gap_end, freq="1s")
            gap_df = pd.DataFrame({
                "timestamp": gap_ts,
                "sent": 0,
                "processed": 0,
            })
            parts = [warmup, gap_df, measured]

    df = pd.concat(parts, ignore_index=True).sort_values("timestamp").reset_index(drop=True)
    df["elapsed_s"] = range(len(df))
    return df


def trim_drain_phase(df: pd.DataFrame) -> pd.DataFrame:
    """Remove trailing drain rows where sent == 0.

    The benchmark tool appends extra seconds after the sending phase ends
    (drain phase) where ``sent == 0`` but ``processed`` may still be > 0.
    Including these rows distorts averages and makes the time-series charts
    appear to have a long tail of zero-sent data.  This helper trims those
    trailing rows so that only the active sending window is plotted.
    """
    if "sent" not in df.columns:
        return df
    # Find last row where sent > 0
    active = df[df["sent"] > 0]
    if active.empty:
        return df
    last_active_idx = active.index[-1]
    trimmed = df.loc[: last_active_idx].copy()
    trimmed["elapsed_s"] = range(len(trimmed))
    return trimmed


def load_all(results_dir: str, thread_counts: list[int]):
    """Return dicts keyed by thread count: {T: DataFrame}.

    Bench DataFrames are returned in two flavours:
      - *benches_full*: raw data including the drain phase.
      - *benches*: trimmed to the active sending window only.
    """
    monitors: dict[int, pd.DataFrame] = {}
    benches: dict[int, pd.DataFrame] = {}
    benches_full: dict[int, pd.DataFrame] = {}
    for t in thread_counts:
        mon_path = os.path.join(results_dir, f"monitor-{t}T.csv")
        ben_path = os.path.join(results_dir, f"bench-{t}T.csv")
        # Try full timeline (warmup + grace + measured)
        full_timeline = load_bench_full_timeline(results_dir, t)
        if full_timeline is not None:
            benches_full[t] = full_timeline
            benches[t] = trim_drain_phase(full_timeline)
        elif os.path.isfile(ben_path):
            full = load_bench(results_dir, t)
            benches_full[t] = full
            benches[t] = trim_drain_phase(full)
        if os.path.isfile(mon_path):
            monitors[t] = load_monitor(results_dir, t)
    return monitors, benches, benches_full


# ---------------------------------------------------------------------------
# Individual time-series comparison charts
# ---------------------------------------------------------------------------

def plot_timeseries_comparison(
    datasets: dict[int, pd.DataFrame],
    x_col: str,
    y_col: str,
    title: str,
    ylabel: str,
    out_path: str,
    figsize=(14, 6),
):
    """Overlay a metric from multiple thread-count runs on one chart."""
    fig, ax = plt.subplots(figsize=figsize)
    for idx, (threads, df) in enumerate(sorted(datasets.items())):
        if y_col not in df.columns:
            continue
        ax.plot(
            df[x_col],
            df[y_col],
            label=f"{threads}T",
            color=thread_color(idx),
            linewidth=1.4,
            alpha=0.85,
        )
    ax.set_title(title, fontsize=14, fontweight="bold")
    ax.set_xlabel("Elapsed time (s)")
    ax.set_ylabel(ylabel)
    ax.legend(title="Threads", loc="upper left", bbox_to_anchor=(1.01, 1))
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


# ---------------------------------------------------------------------------
# Summary bar charts
# ---------------------------------------------------------------------------

def plot_bar_summary(
    labels: list[str],
    values: list[float],
    colors: list[str],
    title: str,
    ylabel: str,
    out_path: str,
    figsize=(10, 6),
):
    """Grouped bar chart comparing a single aggregate value per thread count."""
    fig, ax = plt.subplots(figsize=figsize)
    x = np.arange(len(labels))
    bars = ax.bar(x, values, color=colors, width=0.5, edgecolor="white")

    # Value labels on top of bars
    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() * 1.01,
            f"{val:,.1f}" if isinstance(val, float) else f"{val:,}",
            ha="center",
            va="bottom",
            fontsize=10,
        )

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_xlabel("Orchestrator threads")
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontsize=14, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


# ---------------------------------------------------------------------------
# Dual-axis sent vs processed chart
# ---------------------------------------------------------------------------

def plot_sent_vs_processed(
    benches: dict[int, pd.DataFrame],
    out_path: str,
    figsize=(14, 6),
):
    """One subplot per thread count showing sent & processed per second.

    Uses line charts instead of bar charts so that long runs (60+ seconds)
    remain legible.
    """
    n = len(benches)
    if n == 0:
        return
    cols = min(n, 3)
    rows = (n + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(7 * cols, 5 * rows), squeeze=False)

    for idx, (threads, df) in enumerate(sorted(benches.items())):
        r, c = divmod(idx, cols)
        ax = axes[r][c]
        ax.plot(df["elapsed_s"], df["sent"],
                color=COLORS[0], linewidth=1.3, alpha=0.85, label="Sent")
        ax.plot(df["elapsed_s"], df["processed"],
                color=COLORS[2], linewidth=1.3, alpha=0.85, label="Processed")
        ax.fill_between(df["elapsed_s"], df["sent"], alpha=0.15, color=COLORS[0])
        ax.fill_between(df["elapsed_s"], df["processed"], alpha=0.15, color=COLORS[2])
        ax.set_title(f"{threads} Thread(s)", fontsize=12, fontweight="bold")
        ax.set_xlabel("Elapsed (s)")
        ax.set_ylabel("Events / sec")
        ax.legend(loc="upper right", fontsize=9)
        ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    # Hide unused subplots
    for idx in range(n, rows * cols):
        r, c = divmod(idx, cols)
        axes[r][c].set_visible(False)

    fig.suptitle("Sent vs Processed per second", fontsize=15, fontweight="bold", y=1.02)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


# ---------------------------------------------------------------------------
# Scaling summary chart (bar chart of aggregated totals per thread count)
# ---------------------------------------------------------------------------

def plot_scaling_summary(
    benches: dict[int, pd.DataFrame],
    out_dir: str,
    fmt: str,
):
    """Bar charts: total processed, avg EPS processed, loss % per thread count."""
    labels, colors = [], []
    total_proc_vals, avg_proc_vals, loss_pct_vals = [], [], []

    for idx, (threads, df) in enumerate(sorted(benches.items())):
        labels.append(f"{threads}T")
        colors.append(thread_color(idx))
        total_s = df["sent"].sum()
        total_p = df["processed"].sum()
        total_proc_vals.append(total_p)
        duration = len(df)
        avg_proc_vals.append(total_p / duration if duration > 0 else 0)
        loss_pct_vals.append(
            (total_s - total_p) / total_s * 100 if total_s > 0 else 0
        )

    plot_bar_summary(
        labels, total_proc_vals, colors,
        "Total events processed", "Events",
        os.path.join(out_dir, f"summary_total_processed.{fmt}"),
    )
    plot_bar_summary(
        labels, avg_proc_vals, colors,
        "Avg processed rate (EPS)", "Events / sec",
        os.path.join(out_dir, f"summary_avg_proc_eps.{fmt}"),
    )
    plot_bar_summary(
        labels, loss_pct_vals, colors,
        "Event loss (%)", "Loss %",
        os.path.join(out_dir, f"summary_loss_pct.{fmt}"),
    )


# ---------------------------------------------------------------------------
# Resource scaling summary (avg/peak per thread count)
# ---------------------------------------------------------------------------

def plot_resource_scaling(
    monitors: dict[int, pd.DataFrame],
    out_dir: str,
    fmt: str,
):
    """Bar charts for avg CPU, peak CPU, avg RSS, peak RSS per thread count."""
    labels, colors = [], []
    avg_cpu, peak_cpu, avg_rss, peak_rss = [], [], [], []

    for idx, (threads, df) in enumerate(sorted(monitors.items())):
        labels.append(f"{threads}T")
        colors.append(thread_color(idx))
        avg_cpu.append(df["cpu_pct"].mean())
        peak_cpu.append(df["cpu_pct"].max())
        avg_rss.append(df["rss_mb"].mean())
        peak_rss.append(df["rss_mb"].max())

    plot_bar_summary(
        labels, avg_cpu, colors,
        "Avg CPU usage (absolute %)", "CPU %",
        os.path.join(out_dir, f"summary_avg_cpu.{fmt}"),
    )
    plot_bar_summary(
        labels, peak_cpu, colors,
        "Peak CPU usage (absolute %)", "CPU %",
        os.path.join(out_dir, f"summary_peak_cpu.{fmt}"),
    )
    plot_bar_summary(
        labels, avg_rss, colors,
        "Avg RSS memory", "MB",
        os.path.join(out_dir, f"summary_avg_rss.{fmt}"),
    )
    plot_bar_summary(
        labels, peak_rss, colors,
        "Peak RSS memory", "MB",
        os.path.join(out_dir, f"summary_peak_rss.{fmt}"),
    )


# ---------------------------------------------------------------------------
# Main generation pipeline
# ---------------------------------------------------------------------------

MONITOR_METRICS = [
    ("cpu_pct",     "CPU usage (absolute %)",    "CPU %"),
    ("rss_mb",      "RSS memory",                "MB"),
    ("vms_mb",      "VMS memory",                "MB"),
    ("fds",         "Open file descriptors",     "Count"),
    ("read_ops",    "Cumulative read ops",       "Ops"),
    ("write_ops",   "Cumulative write ops",      "Ops"),
    ("read_bytes",  "Cumulative bytes read",     "Bytes"),
    ("write_bytes", "Cumulative bytes written",  "Bytes"),
    ("disk_pct",    "Disk I/O (%)",              "Disk %"),
]


def generate_all(results_dir: str, out_dir: str, fmt: str):
    os.makedirs(out_dir, exist_ok=True)

    thread_counts = discover_thread_counts(results_dir)
    if not thread_counts:
        print(f"No monitor-*T.csv or bench-*T.csv files found in {results_dir}")
        sys.exit(1)

    print(f"Thread counts detected: {thread_counts}")
    monitors, benches, benches_full = load_all(results_dir, thread_counts)

    # Log trimming information
    for t in sorted(benches.keys()):
        full_len = len(benches_full.get(t, pd.DataFrame()))
        trim_len = len(benches[t])
        if full_len != trim_len:
            print(f"  bench-{t}T.csv: {full_len} rows total, "
                  f"{trim_len} active (trimmed {full_len - trim_len} drain rows)")

    # --- Time-series comparison charts (monitor) ---
    if monitors:
        print("\nMonitor time-series comparisons:")
        for col, title, ylabel in MONITOR_METRICS:
            plot_timeseries_comparison(
                monitors,
                x_col="elapsed_s",
                y_col=col,
                title=f"{title} – thread comparison",
                ylabel=ylabel,
                out_path=os.path.join(out_dir, f"ts_{col}.{fmt}"),
            )

    # --- Time-series comparison charts (bench) ---
    if benches:
        print("\nBenchmark time-series comparisons:")
        plot_timeseries_comparison(
            benches, "elapsed_s", "sent",
            "Events sent per second – thread comparison", "Events / sec",
            os.path.join(out_dir, f"ts_sent.{fmt}"),
        )
        plot_timeseries_comparison(
            benches, "elapsed_s", "processed",
            "Events processed per second – thread comparison", "Events / sec",
            os.path.join(out_dir, f"ts_processed.{fmt}"),
        )

        # Sent vs processed subplots (use full data including drain)
        print("\nSent vs Processed detail:")
        plot_sent_vs_processed(
            benches_full, os.path.join(out_dir, f"detail_sent_vs_processed.{fmt}"),
        )

    # --- Scaling summary bar charts ---
    if benches:
        print("\nScaling summary (bench):")
        plot_scaling_summary(benches, out_dir, fmt)

    if monitors:
        print("\nResource scaling summary (monitor):")
        plot_resource_scaling(monitors, out_dir, fmt)

    print(f"\nDone. All charts saved to {out_dir}/")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="Generate comparison charts from acceptance_test.sh results.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "-r", "--results",
        required=True,
        help="Path to the results directory (output of acceptance_test.sh)",
    )
    p.add_argument(
        "-o", "--output",
        default="./charts",
        help="Directory to save generated charts (default: ./charts)",
    )
    p.add_argument(
        "--format",
        default="png",
        choices=["png", "svg", "pdf"],
        help="Output image format (default: png)",
    )
    args = p.parse_args()

    generate_all(args.results, args.output, args.format)


if __name__ == "__main__":
    main()
