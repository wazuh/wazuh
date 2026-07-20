#!/usr/bin/env python3
from __future__ import annotations
"""
version_comparison.py – Cross-version benchmark visualizer.

Compares benchmark results from the **same hardware** but different code
versions.  Each version is a results directory produced by
``acceptance_test.sh``, potentially containing multiple thread counts
(e.g. bench-4T.csv, bench-8T.csv).

For every thread count found in common across all versions, a full set of
comparison charts is generated.

Usage:
    # Compare two versions (labels auto-derived from dir names)
    python3 version_comparison.py \\
        -r ./results_step_2 \\
        -r ./results_step_3 \\
        -o ./version_charts

    # With explicit labels
    python3 version_comparison.py \\
        -r ./results_step_2::"Baseline" \\
        -r ./results_step_3::"Optimised" \\
        -o ./version_charts
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


def ver_color(idx: int) -> str:
    return COLORS[idx % len(COLORS)]


# ---------------------------------------------------------------------------
# Label helpers
# ---------------------------------------------------------------------------

def label_from_dirname(results_dir: str) -> str:
    name = os.path.basename(os.path.normpath(results_dir))
    name = re.sub(r"^results[_-]?", "", name)
    return name or "unknown"


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def discover_thread_counts(results_dir: str) -> list[int]:
    """Return sorted list of thread counts found in a results dir."""
    pattern = re.compile(r"^bench-(\d+)T\.csv$")
    counts = set()
    for name in os.listdir(results_dir):
        m = pattern.match(name)
        if m:
            counts.add(int(m.group(1)))
    return sorted(counts)


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


def load_bench_full_timeline(results_dir: str, threads: int) -> pd.DataFrame | None:
    """Concatenate warmup + grace-gap + measured bench CSVs."""
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


# ---------------------------------------------------------------------------
# Chart helpers
# ---------------------------------------------------------------------------

def plot_ts(
    datasets: dict[str, pd.DataFrame],
    y_col: str,
    title: str,
    ylabel: str,
    out_path: str,
    figsize=(14, 6),
):
    """Overlay a time-series metric from multiple versions."""
    fig, ax = plt.subplots(figsize=figsize)
    for idx, (label, df) in enumerate(datasets.items()):
        if y_col not in df.columns:
            continue
        ax.plot(
            df["elapsed_s"],
            df[y_col],
            label=label,
            color=ver_color(idx),
            linewidth=1.3,
            alpha=0.85,
        )
    ax.set_title(title, fontsize=14, fontweight="bold")
    ax.set_xlabel("Elapsed time (s)")
    ax.set_ylabel(ylabel)
    ax.legend(title="Version", loc="upper left", bbox_to_anchor=(1.01, 1))
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
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() * 1.01,
            text, ha="center", va="bottom", fontsize=10,
        )
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha="right")
    ax.set_xlabel("Version")
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontsize=14, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


def plot_grouped_bar(
    thread_counts: list[int],
    version_labels: list[str],
    values: dict[str, list[float]],
    title: str,
    ylabel: str,
    out_path: str,
    figsize=(12, 6),
):
    """Grouped bar chart: one group per thread count, one bar per version."""
    fig, ax = plt.subplots(figsize=figsize)
    n_versions = len(version_labels)
    x = np.arange(len(thread_counts))
    width = 0.8 / n_versions

    for idx, label in enumerate(version_labels):
        offset = (idx - n_versions / 2 + 0.5) * width
        vals = values[label]
        bars = ax.bar(x + offset, vals, width, label=label,
                      color=ver_color(idx), edgecolor="white")
        for bar, val in zip(bars, vals):
            text = f"{val:,.1f}" if isinstance(val, float) else f"{val:,}"
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() * 1.01, text,
                    ha="center", va="bottom", fontsize=9)

    ax.set_xticks(x)
    ax.set_xticklabels([f"{t}T" for t in thread_counts])
    ax.set_xlabel("Threads")
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontsize=14, fontweight="bold")
    ax.legend(title="Version")
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


def plot_sent_vs_processed(
    datasets: dict[str, pd.DataFrame],
    title_suffix: str,
    out_path: str,
):
    """Subplot grid: one subplot per version with sent & processed."""
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

    fig.suptitle(f"Sent vs Processed – {title_suffix}",
                 fontsize=15, fontweight="bold", y=1.02)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out_path}")


# ---------------------------------------------------------------------------
# Metric lists
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


# ---------------------------------------------------------------------------
# Main generation
# ---------------------------------------------------------------------------

def generate_all(versions: dict[str, str], out_dir: str, fmt: str):
    """
    Parameters
    ----------
    versions : dict[label, results_dir]
    out_dir  : str
    fmt      : str  (png, svg, pdf)
    """
    os.makedirs(out_dir, exist_ok=True)

    # Discover thread counts per version
    tc_per_version: dict[str, list[int]] = {}
    for label, rdir in versions.items():
        tc_per_version[label] = discover_thread_counts(rdir)
        print(f"  {label}: thread counts = {tc_per_version[label]}")

    # Common thread counts
    common_tc = sorted(
        set.intersection(*(set(tc) for tc in tc_per_version.values()))
    )
    if not common_tc:
        print("ERROR: No thread counts in common across all versions.")
        sys.exit(1)
    print(f"\nCommon thread counts: {common_tc}")

    version_labels = list(versions.keys())

    # -----------------------------------------------------------------------
    # Per thread count: time-series comparison charts
    # -----------------------------------------------------------------------
    for tc in common_tc:
        tag = f"{tc}T"
        print(f"\n{'='*60}")
        print(f"  {tag} – loading data")
        print(f"{'='*60}")

        monitors: dict[str, pd.DataFrame] = {}
        benches: dict[str, pd.DataFrame] = {}
        benches_full: dict[str, pd.DataFrame] = {}

        for label, rdir in versions.items():
            mon_path = os.path.join(rdir, f"monitor-{tc}T.csv")
            full_timeline = load_bench_full_timeline(rdir, tc)
            if full_timeline is not None:
                benches_full[label] = full_timeline
                benches[label] = trim_drain(full_timeline)
                print(f"  {label}: bench-{tag} (full timeline) → "
                      f"{len(full_timeline)} rows ({len(benches[label])} active)")
            else:
                ben_path = os.path.join(rdir, f"bench-{tc}T.csv")
                if os.path.isfile(ben_path):
                    full = load_bench(rdir, tc)
                    benches_full[label] = full
                    benches[label] = trim_drain(full)
                    print(f"  {label}: bench-{tag}.csv → "
                          f"{len(full)} rows ({len(benches[label])} active)")
            if os.path.isfile(mon_path):
                monitors[label] = load_monitor(rdir, tc)
                print(f"  {label}: monitor-{tag}.csv → "
                      f"{len(monitors[label])} rows")

        # --- Monitor time-series ---
        if monitors:
            print(f"\n  Monitor time-series ({tag}):")
            for col, title, ylabel in MONITOR_METRICS:
                plot_ts(
                    monitors, y_col=col,
                    title=f"{title} – {tag} version comparison",
                    ylabel=ylabel,
                    out_path=os.path.join(out_dir, f"ver_{tag}_{col}.{fmt}"),
                )

        # --- Bench time-series ---
        if benches:
            print(f"\n  Bench time-series ({tag}):")
            plot_ts(
                benches, "sent",
                f"Events sent / sec – {tag} version comparison",
                "Events / sec",
                os.path.join(out_dir, f"ver_{tag}_sent.{fmt}"),
            )
            plot_ts(
                benches, "processed",
                f"Events processed / sec – {tag} version comparison",
                "Events / sec",
                os.path.join(out_dir, f"ver_{tag}_processed.{fmt}"),
            )

            # Sent vs processed subplots
            print(f"\n  Sent vs Processed detail ({tag}):")
            plot_sent_vs_processed(
                benches_full,
                title_suffix=f"{tag} version comparison",
                out_path=os.path.join(out_dir, f"ver_{tag}_sent_vs_processed.{fmt}"),
            )

        # --- Per-thread-count bar summaries ---
        if benches:
            print(f"\n  Summary bars ({tag}):")
            labels = list(benches.keys())
            colors = [ver_color(i) for i in range(len(labels))]

            total_proc = [int(df["processed"].sum()) for df in benches.values()]
            avg_eps = [df["processed"].mean() for df in benches.values()]
            loss_pct = []
            for df in benches.values():
                s, p = df["sent"].sum(), df["processed"].sum()
                loss_pct.append((s - p) / s * 100 if s > 0 else 0.0)

            plot_bar(labels, total_proc, colors,
                     f"Total processed – {tag}", "Events",
                     os.path.join(out_dir, f"ver_{tag}_total_processed.{fmt}"))
            plot_bar(labels, avg_eps, colors,
                     f"Avg processed EPS – {tag}", "Events / sec",
                     os.path.join(out_dir, f"ver_{tag}_avg_proc_eps.{fmt}"))
            plot_bar(labels, loss_pct, colors,
                     f"Event loss (%) – {tag}", "Loss %",
                     os.path.join(out_dir, f"ver_{tag}_loss_pct.{fmt}"))

        if monitors:
            labels = list(monitors.keys())
            colors = [ver_color(i) for i in range(len(labels))]
            avg_cpu = [df["cpu_pct"].mean() for df in monitors.values()]
            peak_cpu = [df["cpu_pct"].max() for df in monitors.values()]
            avg_rss = [df["rss_mb"].mean() for df in monitors.values()]
            peak_rss = [df["rss_mb"].max() for df in monitors.values()]

            plot_bar(labels, avg_cpu, colors,
                     f"Avg CPU (%) – {tag}", "CPU %",
                     os.path.join(out_dir, f"ver_{tag}_avg_cpu.{fmt}"))
            plot_bar(labels, peak_cpu, colors,
                     f"Peak CPU (%) – {tag}", "CPU %",
                     os.path.join(out_dir, f"ver_{tag}_peak_cpu.{fmt}"))
            plot_bar(labels, avg_rss, colors,
                     f"Avg RSS (MB) – {tag}", "MB",
                     os.path.join(out_dir, f"ver_{tag}_avg_rss.{fmt}"))
            plot_bar(labels, peak_rss, colors,
                     f"Peak RSS (MB) – {tag}", "MB",
                     os.path.join(out_dir, f"ver_{tag}_peak_rss.{fmt}"))

    # -----------------------------------------------------------------------
    # Cross-thread grouped bar charts (all thread counts side by side)
    # -----------------------------------------------------------------------
    if len(common_tc) > 1:
        print(f"\n{'='*60}")
        print("  Cross-thread grouped summaries")
        print(f"{'='*60}")

        # Collect aggregates: {label: [val_for_tc1, val_for_tc2, ...]}
        total_proc: dict[str, list[float]] = {l: [] for l in version_labels}
        avg_eps: dict[str, list[float]] = {l: [] for l in version_labels}
        loss_pct: dict[str, list[float]] = {l: [] for l in version_labels}
        avg_cpu: dict[str, list[float]] = {l: [] for l in version_labels}
        peak_cpu: dict[str, list[float]] = {l: [] for l in version_labels}
        avg_rss: dict[str, list[float]] = {l: [] for l in version_labels}
        peak_rss: dict[str, list[float]] = {l: [] for l in version_labels}

        for tc in common_tc:
            for label, rdir in versions.items():
                # Bench
                full_tl = load_bench_full_timeline(rdir, tc)
                if full_tl is not None:
                    b = trim_drain(full_tl)
                else:
                    b = trim_drain(load_bench(rdir, tc))
                s, p = b["sent"].sum(), b["processed"].sum()
                total_proc[label].append(float(p))
                avg_eps[label].append(b["processed"].mean())
                loss_pct[label].append((s - p) / s * 100 if s > 0 else 0.0)

                # Monitor
                mon_path = os.path.join(rdir, f"monitor-{tc}T.csv")
                if os.path.isfile(mon_path):
                    m = load_monitor(rdir, tc)
                    avg_cpu[label].append(m["cpu_pct"].mean())
                    peak_cpu[label].append(m["cpu_pct"].max())
                    avg_rss[label].append(m["rss_mb"].mean())
                    peak_rss[label].append(m["rss_mb"].max())

        plot_grouped_bar(common_tc, version_labels, total_proc,
                         "Total processed – version comparison", "Events",
                         os.path.join(out_dir, f"ver_grouped_total_processed.{fmt}"))
        plot_grouped_bar(common_tc, version_labels, avg_eps,
                         "Avg processed EPS – version comparison", "Events / sec",
                         os.path.join(out_dir, f"ver_grouped_avg_proc_eps.{fmt}"))
        plot_grouped_bar(common_tc, version_labels, loss_pct,
                         "Event loss (%) – version comparison", "Loss %",
                         os.path.join(out_dir, f"ver_grouped_loss_pct.{fmt}"))
        if all(avg_cpu[l] for l in version_labels):
            plot_grouped_bar(common_tc, version_labels, avg_cpu,
                             "Avg CPU (%) – version comparison", "CPU %",
                             os.path.join(out_dir, f"ver_grouped_avg_cpu.{fmt}"))
            plot_grouped_bar(common_tc, version_labels, peak_cpu,
                             "Peak CPU (%) – version comparison", "CPU %",
                             os.path.join(out_dir, f"ver_grouped_peak_cpu.{fmt}"))
            plot_grouped_bar(common_tc, version_labels, avg_rss,
                             "Avg RSS (MB) – version comparison", "MB",
                             os.path.join(out_dir, f"ver_grouped_avg_rss.{fmt}"))
            plot_grouped_bar(common_tc, version_labels, peak_rss,
                             "Peak RSS (MB) – version comparison", "MB",
                             os.path.join(out_dir, f"ver_grouped_peak_rss.{fmt}"))

    print(f"\nDone. All charts saved to {out_dir}/")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="Compare benchmark results across different code versions.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "-r", "--results",
        action="append",
        default=[],
        metavar="DIR[::LABEL]",
        help='Path to a results directory.  Optionally append "::Label" '
             "to set a custom label (e.g. -r ./results_v1::Baseline).  "
             "Can be specified multiple times.",
    )
    p.add_argument(
        "-o", "--output",
        default="./version_charts",
        help="Directory to save generated charts (default: ./version_charts)",
    )
    p.add_argument(
        "--format",
        default="png",
        choices=["png", "svg", "pdf"],
        help="Output image format (default: png)",
    )
    args = p.parse_args()

    # Build versions dict: label → directory
    versions: dict[str, str] = {}
    for spec in args.results:
        if "::" in spec:
            path, lbl = spec.rsplit("::", 1)
        else:
            path = spec
            lbl = label_from_dirname(path)
        path = os.path.normpath(path)
        if not os.path.isdir(path):
            p.error(f"Results directory does not exist: {path}")
        versions[lbl] = path

    if len(versions) < 2:
        p.error("Need at least 2 versions to compare.  "
                "Use -r DIR multiple times.")

    print(f"Versions to compare ({len(versions)}):")
    for lbl, d in versions.items():
        print(f"  [{lbl}] → {d}")
    print()

    generate_all(versions, args.output, args.format)


if __name__ == "__main__":
    main()
