#!/usr/bin/env python3
from __future__ import annotations
"""
hardware_comparison.py – Cross-hardware benchmark visualizer.

Compares the same benchmark run (same thread count) across multiple
hardware environments.  Each environment is a results directory produced
by ``acceptance_test.sh``.

The hardware label is derived automatically from the directory name
(e.g. ``results_amd_amz`` → ``amd_amz``) or from ``system_report.txt``
if present, but can also be overridden via CLI.

Usage:
    # Auto-label from directory names
    python3 hardware_comparison.py \\
        -r /path/to/results_amd_amz \\
        -r /path/to/results_arm_ubuntu \\
        -o ./hw_charts

    # Explicit labels
    python3 hardware_comparison.py \\
        -r /path/to/results_amd_amz::"AMD EPYC (Amazon)" \\
        -r /path/to/results_arm_ubuntu::"ARM Graviton (Ubuntu)" \\
        -o ./hw_charts

    # With a parent directory containing multiple results_* dirs
    python3 hardware_comparison.py \\
        --scan /path/to/results \\
        -o ./hw_charts
"""

import argparse
import os
import re
import sys
from pathlib import Path

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


def env_color(idx: int) -> str:
    return COLORS[idx % len(COLORS)]


# ---------------------------------------------------------------------------
# Label extraction
# ---------------------------------------------------------------------------

def label_from_report(results_dir: str) -> str | None:
    """Try to build a short label from system_report.txt."""
    report = os.path.join(results_dir, "system_report.txt")
    if not os.path.isfile(report):
        return None
    model = arch = os_name = ""
    with open(report) as f:
        for line in f:
            if line.startswith("Model:"):
                model = line.split(":", 1)[1].strip()
            elif line.startswith("Architecture:"):
                arch = line.split(":", 1)[1].strip()
            elif line.startswith("OS:"):
                os_name = line.split(":", 1)[1].strip()
    if model:
        # e.g. "AMD EPYC 7R32 – x86_64 – Amazon Linux 2023"
        parts = [model]
        if arch:
            parts.append(arch)
        if os_name:
            # Keep just the distro name, drop version noise
            short_os = os_name.split()[0:2]
            parts.append(" ".join(short_os))
        return " – ".join(parts)
    return None


def label_from_dirname(results_dir: str) -> str:
    """Derive a human label from the directory name."""
    name = os.path.basename(os.path.normpath(results_dir))
    # Strip common prefixes like "results_"
    name = re.sub(r"^results[_-]?", "", name)
    return name or "unknown"


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def find_thread_count(results_dir: str) -> int | None:
    """Return the (single) thread count present in a results dir, or None."""
    pattern = re.compile(r"^bench-(\d+)T\.csv$")
    for name in os.listdir(results_dir):
        m = pattern.match(name)
        if m:
            return int(m.group(1))
    return None


def load_bench(results_dir: str, threads: int) -> pd.DataFrame:
    path = os.path.join(results_dir, f"bench-{threads}T.csv")
    df = pd.read_csv(path, parse_dates=["timestamp"])
    df["elapsed_s"] = range(len(df))
    return df


def load_monitor(results_dir: str, threads: int) -> pd.DataFrame:
    path = os.path.join(results_dir, f"monitor-{threads}T.csv")
    df = pd.read_csv(path, parse_dates=["timestamp"])
    df["elapsed_s"] = range(len(df))
    return df


def trim_drain(df: pd.DataFrame) -> pd.DataFrame:
    """Remove trailing rows where sent == 0 (drain phase)."""
    if "sent" not in df.columns:
        return df
    active = df[df["sent"] > 0]
    if active.empty:
        return df
    trimmed = df.loc[: active.index[-1]].copy()
    trimmed["elapsed_s"] = range(len(trimmed))
    return trimmed


def load_bench_full_timeline(results_dir: str, threads: int) -> pd.DataFrame | None:
    """Concatenate warmup + grace-gap + measured bench CSVs.

    Returns a single DataFrame covering the entire benchmark timeline,
    or None if both files are missing.
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


# ---------------------------------------------------------------------------
# Chart helpers
# ---------------------------------------------------------------------------

def plot_ts_comparison(
    datasets: dict[str, pd.DataFrame],
    y_col: str,
    title: str,
    ylabel: str,
    out_path: str,
    figsize=(14, 6),
):
    """Overlay a time-series metric from multiple environments."""
    fig, ax = plt.subplots(figsize=figsize)
    for idx, (label, df) in enumerate(datasets.items()):
        if y_col not in df.columns:
            continue
        ax.plot(
            df["elapsed_s"],
            df[y_col],
            label=label,
            color=env_color(idx),
            linewidth=1.3,
            alpha=0.85,
        )
    ax.set_title(title, fontsize=14, fontweight="bold")
    ax.set_xlabel("Elapsed time (s)")
    ax.set_ylabel(ylabel)
    ax.legend(title="Environment", loc="upper left", bbox_to_anchor=(1.01, 1))
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
    """Bar chart comparing an aggregate across environments."""
    fig, ax = plt.subplots(figsize=figsize)
    x = np.arange(len(labels))
    bars = ax.bar(x, values, color=colors, width=0.5, edgecolor="white")

    for bar, val in zip(bars, values):
        text = f"{val:,.1f}" if isinstance(val, float) else f"{val:,}"
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() * 1.01,
            text,
            ha="center",
            va="bottom",
            fontsize=10,
        )

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha="right")
    ax.set_xlabel("Environment")
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontsize=14, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


def plot_sent_vs_processed(
    datasets: dict[str, pd.DataFrame],
    out_path: str,
):
    """Subplot grid: one subplot per environment with sent & processed."""
    n = len(datasets)
    if n == 0:
        return
    cols = min(n, 2)
    rows = (n + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(8 * cols, 5 * rows), squeeze=False)

    for idx, (label, df) in enumerate(datasets.items()):
        r, c = divmod(idx, cols)
        ax = axes[r][c]
        ax.plot(df["elapsed_s"], df["sent"],
                color=COLORS[0], linewidth=1.2, alpha=0.85, label="Sent")
        ax.plot(df["elapsed_s"], df["processed"],
                color=COLORS[2], linewidth=1.2, alpha=0.85, label="Processed")
        ax.fill_between(df["elapsed_s"], df["sent"], alpha=0.12, color=COLORS[0])
        ax.fill_between(df["elapsed_s"], df["processed"], alpha=0.12, color=COLORS[2])
        ax.set_title(label, fontsize=12, fontweight="bold")
        ax.set_xlabel("Elapsed (s)")
        ax.set_ylabel("Events / sec")
        ax.legend(loc="upper right", fontsize=9)
        ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    for idx in range(n, rows * cols):
        r, c = divmod(idx, cols)
        axes[r][c].set_visible(False)

    fig.suptitle("Sent vs Processed – hardware comparison",
                 fontsize=15, fontweight="bold", y=1.02)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


# ---------------------------------------------------------------------------
# Main generation
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


def generate_all(envs: dict[str, str], out_dir: str, fmt: str):
    """
    Parameters
    ----------
    envs : dict[label, results_dir]
        Mapping from human label to results directory path.
    out_dir : str
        Where to write chart images.
    fmt : str
        Image format (png, svg, pdf).
    """
    os.makedirs(out_dir, exist_ok=True)

    # Discover thread count (must be the same across all dirs)
    thread_counts: dict[str, int] = {}
    for label, rdir in envs.items():
        tc = find_thread_count(rdir)
        if tc is None:
            print(f"WARNING: No bench-*T.csv found in {rdir}, skipping '{label}'.")
            continue
        thread_counts[label] = tc

    if not thread_counts:
        print("No benchmark data found in any directory.")
        sys.exit(1)

    unique_tc = set(thread_counts.values())
    if len(unique_tc) > 1:
        print(f"WARNING: Mixed thread counts detected: {thread_counts}")
        print("  Charts will still be generated, but comparison may not be meaningful.")

    # Load data
    monitors: dict[str, pd.DataFrame] = {}
    benches: dict[str, pd.DataFrame] = {}
    benches_full: dict[str, pd.DataFrame] = {}

    for label, rdir in envs.items():
        tc = thread_counts.get(label)
        if tc is None:
            continue
        mon_path = os.path.join(rdir, f"monitor-{tc}T.csv")
        ben_path = os.path.join(rdir, f"bench-{tc}T.csv")
        # Try full timeline (warmup + grace + measured)
        full_timeline = load_bench_full_timeline(rdir, tc)
        if full_timeline is not None:
            benches_full[label] = full_timeline
            benches[label] = trim_drain(full_timeline)
            print(f"  {label}: bench-{tc}T (full timeline) → {len(full_timeline)} rows "
                  f"({len(benches[label])} active)")
        elif os.path.isfile(ben_path):
            full = load_bench(rdir, tc)
            benches_full[label] = full
            benches[label] = trim_drain(full)
            print(f"  {label}: bench-{tc}T.csv → {len(full)} rows "
                  f"({len(benches[label])} active)")
        if os.path.isfile(mon_path):
            monitors[label] = load_monitor(rdir, tc)
            print(f"  {label}: monitor-{tc}T.csv → {len(monitors[label])} rows")

    tc_label = f"{list(unique_tc)[0]}T" if len(unique_tc) == 1 else "mixed"

    # --- Time-series: monitor metrics ---
    if monitors:
        print("\nMonitor time-series comparisons:")
        for col, title, ylabel in MONITOR_METRICS:
            plot_ts_comparison(
                monitors,
                y_col=col,
                title=f"{title} – {tc_label} hardware comparison",
                ylabel=ylabel,
                out_path=os.path.join(out_dir, f"hw_ts_{col}.{fmt}"),
            )

    # --- Time-series: bench metrics ---
    if benches:
        print("\nBenchmark time-series comparisons:")
        plot_ts_comparison(
            benches, "sent",
            f"Events sent / sec – {tc_label} hardware comparison", "Events / sec",
            os.path.join(out_dir, f"hw_ts_sent.{fmt}"),
        )
        plot_ts_comparison(
            benches, "processed",
            f"Events processed / sec – {tc_label} hardware comparison", "Events / sec",
            os.path.join(out_dir, f"hw_ts_processed.{fmt}"),
        )

        # Sent vs processed subplots
        print("\nSent vs Processed detail:")
        plot_sent_vs_processed(
            benches_full,
            os.path.join(out_dir, f"hw_detail_sent_vs_processed.{fmt}"),
        )

    # --- Summary bar charts ---
    if benches:
        print("\nScaling summary (bench):")
        labels = list(benches.keys())
        colors = [env_color(i) for i in range(len(labels))]

        total_proc = [int(df["processed"].sum()) for df in benches.values()]
        avg_eps = [df["processed"].mean() for df in benches.values()]
        loss_pct = []
        for df in benches.values():
            s, p = df["sent"].sum(), df["processed"].sum()
            loss_pct.append((s - p) / s * 100 if s > 0 else 0.0)

        plot_bar(labels, total_proc, colors,
                 f"Total events processed – {tc_label}", "Events",
                 os.path.join(out_dir, f"hw_summary_total_processed.{fmt}"))
        plot_bar(labels, avg_eps, colors,
                 f"Avg processed rate (EPS) – {tc_label}", "Events / sec",
                 os.path.join(out_dir, f"hw_summary_avg_proc_eps.{fmt}"))
        plot_bar(labels, loss_pct, colors,
                 f"Event loss (%) – {tc_label}", "Loss %",
                 os.path.join(out_dir, f"hw_summary_loss_pct.{fmt}"))

    if monitors:
        print("\nResource scaling summary (monitor):")
        labels = list(monitors.keys())
        colors = [env_color(i) for i in range(len(labels))]

        avg_cpu = [df["cpu_pct"].mean() for df in monitors.values()]
        peak_cpu = [df["cpu_pct"].max() for df in monitors.values()]
        avg_rss = [df["rss_mb"].mean() for df in monitors.values()]
        peak_rss = [df["rss_mb"].max() for df in monitors.values()]

        plot_bar(labels, avg_cpu, colors,
                 f"Avg CPU (%) – {tc_label}", "CPU %",
                 os.path.join(out_dir, f"hw_summary_avg_cpu.{fmt}"))
        plot_bar(labels, peak_cpu, colors,
                 f"Peak CPU (%) – {tc_label}", "CPU %",
                 os.path.join(out_dir, f"hw_summary_peak_cpu.{fmt}"))
        plot_bar(labels, avg_rss, colors,
                 f"Avg RSS (MB) – {tc_label}", "MB",
                 os.path.join(out_dir, f"hw_summary_avg_rss.{fmt}"))
        plot_bar(labels, peak_rss, colors,
                 f"Peak RSS (MB) – {tc_label}", "MB",
                 os.path.join(out_dir, f"hw_summary_peak_rss.{fmt}"))

    print(f"\nDone. All charts saved to {out_dir}/")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="Compare benchmark results across different hardware environments.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "-r", "--results",
        action="append",
        default=[],
        metavar="DIR[::LABEL]",
        help='Path to a results directory.  Optionally append "::Label" '
             "to set a custom label (e.g. -r ./results_amd::AMD).  "
             "Can be specified multiple times.",
    )
    p.add_argument(
        "--scan",
        metavar="PARENT_DIR",
        help="Scan a parent directory for results_* subdirectories "
             "and compare all of them.",
    )
    p.add_argument(
        "-o", "--output",
        default="./hw_charts",
        help="Directory to save generated charts (default: ./hw_charts)",
    )
    p.add_argument(
        "--format",
        default="png",
        choices=["png", "svg", "pdf"],
        help="Output image format (default: png)",
    )
    args = p.parse_args()

    # Build env dict: label → directory
    envs: dict[str, str] = {}

    # From --scan
    if args.scan:
        parent = args.scan
        if not os.path.isdir(parent):
            p.error(f"--scan directory does not exist: {parent}")
        for entry in sorted(os.listdir(parent)):
            full = os.path.join(parent, entry)
            if os.path.isdir(full) and os.path.isfile(os.path.join(full, "bench-4T.csv") if False else ""):
                pass
            # Accept any subdir that contains at least one bench-*T.csv
            if os.path.isdir(full):
                has_bench = any(
                    re.match(r"^bench-\d+T\.csv$", f)
                    for f in os.listdir(full)
                )
                if has_bench:
                    lbl = label_from_report(full) or label_from_dirname(full)
                    envs[lbl] = full

    # From -r flags
    for spec in args.results:
        if "::" in spec:
            path, lbl = spec.rsplit("::", 1)
        else:
            path = spec
            lbl = label_from_report(path) or label_from_dirname(path)
        path = os.path.normpath(path)
        if not os.path.isdir(path):
            p.error(f"Results directory does not exist: {path}")
        envs[lbl] = path

    if len(envs) < 2:
        p.error("Need at least 2 environments to compare.  "
                "Use -r DIR multiple times, or --scan PARENT_DIR.")

    print(f"Environments to compare ({len(envs)}):")
    for lbl, d in envs.items():
        print(f"  [{lbl}] → {d}")
    print()

    generate_all(envs, args.output, args.format)


if __name__ == "__main__":
    main()
