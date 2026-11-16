#!/usr/bin/env python3
"""Create privacy-preserving tables, scientific plots, and a standalone HTML report."""
import argparse
import base64
import csv
import html
import json
import re
from pathlib import Path
import statistics

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

MIB = 1024 ** 2
COLORS = {"gzip": "#cf742c", "zstd": "#26728e"}
KINDS = ("alerts-log", "alerts-json", "archives-json")
LABELS = {"alerts-log": "Alerts · text", "alerts-json": "Alerts · JSON", "archives-json": "Archives · JSON", "all": "Sample total"}


def median(values):
    return float(statistics.median(values))


def csv_file(path, rows):
    with path.open("w", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def analyze(folder):
    rows = [json.loads(line) for line in (folder / "trials.jsonl").read_text().splitlines()]
    assert all(row["verified"] for row in rows)
    manifest = json.loads((folder / "corpus.json").read_text())
    per_file = []
    for item in manifest:
        for algorithm in ("gzip", "zstd"):
            measured = [r for r in rows if r["dataset"] == item["id"] and r["algorithm"] == algorithm and not r["warmup"]]
            compressed = [r for r in measured if r["operation"] == "compress"]
            decoded = [r for r in measured if r["operation"] == "decompress"]
            assert len(compressed) == len(decoded) > 0
            size = compressed[0]["compressed_bytes"]
            assert all(r["compressed_bytes"] == size for r in compressed)
            per_file.append(dict(dataset=item["id"], day=item["day"], kind=item["kind"], algorithm=algorithm,
                                 raw_bytes=item["sample_bytes"], compressed_bytes=size,
                                 compression_ratio=item["sample_bytes"] / size,
                                 compression_wall_s=median(r["wall_s"] for r in compressed),
                                 compression_cpu_s=median(r["cpu_s"] for r in compressed),
                                 compression_rss_kib=median(r["max_rss_kib"] for r in compressed),
                                 decompression_wall_s=median(r["wall_s"] for r in decoded),
                                 decompression_cpu_s=median(r["cpu_s"] for r in decoded), repetitions=len(compressed)))
    summaries = []
    for kind in list(KINDS) + ["all"]:
        for algorithm in ("gzip", "zstd"):
            group = [r for r in per_file if r["algorithm"] == algorithm and (kind == "all" or r["kind"] == kind)]
            if not group:
                continue
            raw, compressed = sum(r["raw_bytes"] for r in group), sum(r["compressed_bytes"] for r in group)
            comp, dec = sum(r["compression_wall_s"] for r in group), sum(r["decompression_wall_s"] for r in group)
            summaries.append(dict(kind=kind, algorithm=algorithm, raw_bytes=raw, compressed_bytes=compressed,
                                  compression_ratio=raw / compressed, compression_wall_s=comp,
                                  compression_mib_s=raw / MIB / comp,
                                  compression_cpu_s=sum(r["compression_cpu_s"] for r in group),
                                  decompression_wall_s=dec, decompression_mib_s=raw / MIB / dec,
                                  median_process_rss_mib=median(r["compression_rss_kib"] for r in group) / 1024))
    return rows, manifest, per_file, summaries


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--primary", type=Path, required=True)
    parser.add_argument("--full", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-version", default="not recorded")
    args = parser.parse_args()
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    rows, manifest, per_file, summary = analyze(args.primary)
    full_rows, full_manifest, full_files, full_summary = analyze(args.full)
    environment = json.loads((args.primary / "environment.json").read_text())
    all_rows = rows + full_rows
    csv_file(output / "measured-trials.csv", [dict(r, cohort="full-file" if r in full_rows else "primary") for r in all_rows if not r["warmup"]])
    csv_file(output / "per-file-medians.csv", per_file + full_files)
    csv_file(output / "category-summary.csv", summary)
    environment["source_manager_version_at_collection"] = args.source_version
    environment["analysis_versions"] = {"numpy": np.__version__, "matplotlib": matplotlib.__version__}
    (output / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")
    (output / "corpus-manifest.json").write_text(json.dumps(manifest + full_manifest, indent=2) + "\n")

    def get(kind, algorithm, source=summary):
        return next(row for row in source if row["kind"] == kind and row["algorithm"] == algorithm)

    # Paired day-cluster bootstrap: describes variation within this sampled week.
    # It is not a confidence interval for the population of Wazuh installations.
    rng = np.random.default_rng(20261116)
    bootstrap = []
    days = sorted(set(row["day"] for row in per_file))
    for _ in range(10000):
        selected = rng.choice(days, len(days), replace=True)
        totals = {algorithm: {"size": 0.0, "wall": 0.0} for algorithm in COLORS}
        for day in selected:
            for algorithm in COLORS:
                group = [r for r in per_file if r["day"] == day and r["algorithm"] == algorithm]
                totals[algorithm]["size"] += sum(r["compressed_bytes"] for r in group)
                totals[algorithm]["wall"] += sum(r["compression_wall_s"] for r in group)
        bootstrap.append((100 * (1 - totals["zstd"]["size"] / totals["gzip"]["size"]),
                          totals["gzip"]["wall"] / totals["zstd"]["wall"]))
    intervals = np.percentile(np.asarray(bootstrap), [2.5, 97.5], axis=0)
    improvements = []
    for kind in list(KINDS) + ["all"]:
        g, z = get(kind, "gzip"), get(kind, "zstd")
        improvements.append(dict(kind=kind, compressed_size_reduction_pct=100 * (1-z["compressed_bytes"]/g["compressed_bytes"]),
                                 compression_speedup=g["compression_wall_s"]/z["compression_wall_s"],
                                 cpu_reduction_pct=100 * (1-z["compression_cpu_s"]/g["compression_cpu_s"]),
                                 decompression_speedup=g["decompression_wall_s"]/z["decompression_wall_s"]))
    csv_file(output / "comparisons.csv", improvements)

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.spines.top": False,
                         "axes.spines.right": False, "axes.titleweight": "bold", "axes.labelcolor": "#29333b",
                         "text.color": "#202a32", "figure.facecolor": "white", "savefig.facecolor": "white"})
    figures = []

    def save(fig, name, caption):
        fig.tight_layout(pad=1.8)
        fig.savefig(output / f"{name}.png", dpi=180, bbox_inches="tight")
        fig.savefig(output / f"{name}.svg", bbox_inches="tight")
        plt.close(fig)
        figures.append((name, caption))

    def paired_bars(axis, kinds, field, source=summary, scale=1.0):
        x = np.arange(len(kinds))
        for offset, algorithm in ((-.19, "gzip"), (.19, "zstd")):
            values = [get(kind, algorithm, source)[field] / scale for kind in kinds]
            bars = axis.bar(x+offset, values, width=.36, color=COLORS[algorithm], label=algorithm)
            axis.bar_label(bars, fmt="%.2f", padding=3, fontsize=9)
        axis.set_xticks(x)
        axis.set_xticklabels([LABELS[kind] for kind in kinds])
        axis.grid(axis="y", alpha=.18)
        axis.set_axisbelow(True)
        axis.margins(y=.18)

    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.8))
    paired_bars(axes[0], KINDS, "compressed_bytes", scale=MIB)
    axes[0].set(title="Compressed output by log type", ylabel="MiB · lower is better")
    paired_bars(axes[1], KINDS, "compression_ratio")
    axes[1].set(title="Compression ratio", ylabel="Uncompressed bytes / compressed bytes")
    axes[0].legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=2, frameon=False)
    save(fig, "01-storage", "Actual production compressor output, seven days per log type. Archives use stratified windows; alert files are complete.")

    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.8))
    paired_bars(axes[0], KINDS, "compression_mib_s")
    axes[0].set(title="Compression throughput", ylabel="Uncompressed MiB/s · higher is better")
    paired_bars(axes[1], KINDS, "decompression_mib_s")
    axes[1].set(title="Library readback throughput", ylabel="Restored MiB/s · higher is better")
    axes[0].legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=2, frameon=False)
    save(fig, "02-throughput", "Aggregate throughput = total raw bytes / sum of per-file median elapsed times. Readback is a separate common streaming decoder benchmark.")

    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.8))
    paired_bars(axes[0], KINDS, "compression_cpu_s")
    axes[0].set(title="Compression CPU time", ylabel="User + system CPU seconds · lower is better")
    paired_bars(axes[1], KINDS, "median_process_rss_mib")
    baseline = median(r["max_rss_kib"] for r in rows if r["operation"] == "baseline") / 1024
    axes[1].axhline(baseline, color="#555", linestyle="--", label="Startup floor")
    axes[1].set(title="Peak RSS of executed driver", ylabel="Median process peak MiB · includes startup")
    axes[0].legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=2, frameon=False)
    axes[1].legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=3, frameon=False, fontsize=8)
    save(fig, "03-cpu-memory", "CPU time is measured around compression only. VmHWM excludes Python's inherited pre-exec peak but includes driver/configuration memory.")

    heat = []
    for kind in KINDS:
        line = []
        for day in days:
            group = [r for r in per_file if r["kind"] == kind and r["day"] == day]
            g = next(r["compressed_bytes"] for r in group if r["algorithm"] == "gzip")
            z = next(r["compressed_bytes"] for r in group if r["algorithm"] == "zstd")
            line.append(100*(1-z/g))
        heat.append(line)
    heat = np.asarray(heat)
    fig, axis = plt.subplots(figsize=(11.5, 4.0))
    limit = max(abs(heat.min()), abs(heat.max()), 1)
    picture = axis.imshow(heat, cmap="RdBu", vmin=-limit, vmax=limit, aspect="auto")
    for i in range(len(KINDS)):
        for j in range(len(days)):
            axis.text(j, i, f"{heat[i,j]:.1f}%", ha="center", va="center", color="white" if abs(heat[i,j]) > .55*limit else "#202a32")
    axis.set_xticks(np.arange(len(days)))
    axis.set_xticklabels([f"Day {day}" for day in days])
    axis.set_yticks(np.arange(len(KINDS)))
    axis.set_yticklabels([LABELS[kind] for kind in KINDS])
    axis.set_title("Zstd output reduction relative to gzip, by day")
    fig.colorbar(picture, ax=axis, label="Positive = zstd is smaller")
    save(fig, "04-day-variation", "Every dataset is shown, including any cases where zstd produces a larger file. Dates and server identifiers are not exposed.")

    fig, axis = plt.subplots(figsize=(11.5, 5.0))
    for offset, algorithm in ((-.14, "gzip"), (.14, "zstd")):
        positions, values = [], []
        for i, kind in enumerate(KINDS):
            group = [r for r in rows if not r["warmup"] and r["operation"] == "compress" and r["algorithm"] == algorithm and r["kind"] == kind]
            positions.append(i+offset)
            values.append([1000*r["wall_s"]/(r["raw_bytes"]/MIB) for r in group])
        boxes = axis.boxplot(values, positions=positions, widths=.24, patch_artist=True, manage_ticks=False,
                             medianprops={"color": "#111"}, flierprops={"marker": ".", "markersize": 3})
        for box in boxes["boxes"]:
            box.set_facecolor(COLORS[algorithm]); box.set_alpha(.8)
        axis.plot([], [], color=COLORS[algorithm], linewidth=8, label=algorithm)
    axis.set_xticks(range(len(KINDS)))
    axis.set_xticklabels([LABELS[kind] for kind in KINDS])
    axis.set(ylabel="Compression ms per uncompressed MiB · lower is better", title="All measured per-file timing observations")
    axis.grid(axis="y", alpha=.18)
    axis.legend(frameon=False)
    save(fig, "05-timing-distribution", "Seven repetitions × seven days per log type and method. Warm-up is excluded; boxes show the median and interquartile range.")

    daily = [r for r in rows if r["operation"] == "daily" and not r["warmup"]]
    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.8))
    for axis, field, title in ((axes[0], "wall_s", "Signing + compression: elapsed time"),
                               (axes[1], "cpu_s", "Signing + compression: CPU time")):
        for index, algorithm in enumerate(COLORS):
            values = [r[field] for r in daily if r["algorithm"] == algorithm]
            center = median(values)
            axis.bar(index, center, width=.55, color=COLORS[algorithm])
            axis.scatter(np.repeat(index, len(values)), values, color="#26323b", s=18, zorder=3)
            axis.text(index, max(values)*1.05, f"{center:.2f}s", ha="center")
        axis.set_xticks([0,1]);axis.set_xticklabels(list(COLORS))
        axis.set(title=title, ylabel="Seconds · lower is better")
        axis.margins(y=.2);axis.grid(axis="y",alpha=.18);axis.set_axisbelow(True)
    save(fig, "06-production-batch", "Five measured repetitions through production manage_files(), including checksum generation and compression of the 21-file corpus. Setup and verification are excluded.")

    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.8))
    ids = [item["id"] for item in full_manifest]
    for offset, algorithm in ((-.19,"gzip"),(.19,"zstd")):
        group=[next(r for r in full_files if r["dataset"]==name and r["algorithm"]==algorithm) for name in ids]
        x=np.arange(len(ids))+offset
        bars=axes[0].bar(x,[r["compressed_bytes"]/MIB for r in group],width=.36,color=COLORS[algorithm],label=algorithm)
        axes[0].bar_label(bars,fmt="%.2f",padding=3)
        bars=axes[1].bar(x,[r["raw_bytes"]/MIB/r["compression_wall_s"] for r in group],width=.36,color=COLORS[algorithm])
        axes[1].bar_label(bars,fmt="%.1f",padding=3)
    for axis in axes:
        axis.set_xticks(np.arange(len(ids)));axis.set_xticklabels(["Complete archive · day 1","Complete archive · day 7"])
        axis.grid(axis="y",alpha=.18);axis.set_axisbelow(True);axis.margins(y=.18)
    axes[0].set(title="Complete archives: output size",ylabel="MiB · lower is better")
    axes[1].set(title="Complete archives: throughput",ylabel="Uncompressed MiB/s · higher is better")
    axes[0].legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=2, frameon=False)
    save(fig,"07-full-archives","Two full daily JSON archives, three measured repetitions per method. These overlap the sampled days and are not added again to primary totals.")

    g,z=get("all","gzip"),get("all","zstd")
    saving=100*(1-z["compressed_bytes"]/g["compressed_bytes"])
    speedup=g["compression_wall_s"]/z["compression_wall_s"]
    size_description=f"{abs(saving):.2f}% {'smaller' if saving >= 0 else 'larger'}"
    daily_g=median(r["wall_s"] for r in daily if r["algorithm"]=="gzip")
    daily_z=median(r["wall_s"] for r in daily if r["algorithm"]=="zstd")
    full_g,full_z=get("all","gzip",full_summary),get("all","zstd",full_summary)
    cpu_model=next((item["data"] for item in environment["cpu_info"]["lscpu"] if item["field"]=="Model name:"),"Unknown")
    category_lines=[]
    for kind in KINDS:
        a,b=get(kind,"gzip"),get(kind,"zstd")
        category_lines.append(f"| {LABELS[kind]} | {a['raw_bytes']/MIB:.2f} | {a['compressed_bytes']/MIB:.2f} | {b['compressed_bytes']/MIB:.2f} | {100*(1-b['compressed_bytes']/a['compressed_bytes']):.2f}% | {a['compression_wall_s']/b['compression_wall_s']:.2f}× |")
    full_lines=[]
    for name in ids:
        a=next(r for r in full_files if r["dataset"]==name and r["algorithm"]=="gzip")
        b=next(r for r in full_files if r["dataset"]==name and r["algorithm"]=="zstd")
        full_lines.append(f"| {name} | {a['raw_bytes']/MIB:.2f} | {a['compressed_bytes']/MIB:.2f} | {b['compressed_bytes']/MIB:.2f} | {100*(1-b['compressed_bytes']/a['compressed_bytes']):.2f}% | {a['compression_wall_s']/b['compression_wall_s']:.2f}× |")
    text=f"""# Wazuh manager: gzip versus zstd on real supervision logs

## Findings

For the primary 21-file corpus, zstd level 3 produced **{size_description} output** than the existing gzip default (level 6), and compression was **{speedup:.2f}× as fast** by the aggregate of per-file median wall times. This is the result for this specific corpus and host, not a universal guarantee.

Production signing plus compression of the same corpus took **{daily_g:.3f}s with gzip** and **{daily_z:.3f}s with zstd**, a **{daily_g/daily_z:.2f}× speedup**. The two complete JSON archive files independently checked the sampled archive behavior: combined output changed by **{100*(1-full_z['compressed_bytes']/full_g['compressed_bytes']):.2f}%** and aggregate compression speedup was **{full_g['compression_wall_s']/full_z['compression_wall_s']:.2f}×**.

Compression CPU time for the primary corpus fell by **{100*(1-z['compression_cpu_s']/g['compression_cpu_s']):.2f}%**. Median standalone-driver peak RSS was **{g['median_process_rss_mib']:.2f} MiB with gzip** and **{z['median_process_rss_mib']:.2f} MiB with zstd**; this is a memory tradeoff, not the full daemon footprint. Readback throughput improved by **{g['decompression_wall_s']/z['decompression_wall_s']:.2f}×** in the separate common decoder harness. The unchanged signing work reduces the end-to-end gain relative to compression alone.

Every compressed output was read back and matched its original SHA-256. Raw logs, server addresses, usernames, and log excerpts are excluded from this report.

## Corpus and sampling

The source manager reported `{args.source_version}` at collection time; this is provenance, not the benchmark binary version. The primary corpus contains seven consecutive completed days: seven complete alert text files, seven complete alert JSON files, and seven sampled JSON archive files. The text archive was empty on the source server and is therefore not represented. Newline counts describe lines, not alert/event counts.

The {sum(item['source_bytes'] for item in manifest)/2**30:.3f} GiB source corpus yielded {sum(item['sample_bytes'] for item in manifest)/MIB:.2f} MiB of primary benchmark input. Each archive contributes three approximately 32 MiB windows from the beginning, middle, and end. Partial boundary lines were removed and windows concatenated in order. Full gzip sources were streamed to EOF with CRC validation and stable size/mtime checks during collection. Raw sample SHA-256 hashes were verified after transfer. Collection used a read-only, low-priority pass; no benchmark ran on the source server.

Alerts were retained in full while archives were sampled. This intentionally oversamples alerts relative to original source volume. **The sample-total result is not a production-volume-weighted estimate of the complete week.** Results by log type and two complete archive days are provided to expose that limitation. No data or day was selected based on compression outcome.

## Production defaults: measured size and speed

| Dataset type | Raw MiB | Gzip MiB | Zstd MiB | Zstd output reduction vs gzip | Compression speedup |
|---|---:|---:|---:|---:|---:|
{chr(10).join(category_lines)}

## Complete archive cross-check

| Complete file | Raw MiB | Gzip MiB | Zstd MiB | Zstd output reduction vs gzip | Compression speedup |
|---|---:|---:|---:|---:|---:|
{chr(10).join(full_lines)}

These two files are full day-1 and day-7 archives from the same week. They validate large-file behavior and sampling sensitivity, but are not independent new days and are not double-counted in primary totals.

## Measurement protocol

- Execute the actual production `OS_CompressLog()` and `OS_CompressLogZstd()` routines, selected through the shared `ossec.conf` configuration reader. Do not substitute CLI compressors or tune levels after observing results.
- Gzip uses zlib {rows[0]['zlib_version']} default compression, equivalent to level 6. Zstd uses library {rows[0]['zstd_version']} default level 3. Both use their existing streaming configuration and one thread.
- Framing/window settings are the production defaults, not matched tuning knobs: gzip includes its mandatory CRC32 and a 32 KiB DEFLATE window; the current zstd stream uses a 2 MiB window and its optional frame checksum is off. Existing Wazuh `.sum` generation is unchanged, and benchmark readback is independently SHA-256 verified. Enabling zstd frame checksums would be a separate implementation/configuration change requiring remeasurement.
- Fresh production build of commit `{environment['source_commit']}` with the standalone benchmark harness; no sanitizer or profiling preload. Build command: `make TARGET=server -f Makefile -f ../tests/compression/benchmark/Makefile compression-benchmark`.
- Pin the driver to logical CPU {environment['affinity'][0]} in Docker Desktop's Linux VM. VM reports {environment['logical_cpus']} logical CPUs and {environment['memory_bytes']/2**30:.2f} GiB RAM; CPU model: {cpu_model}. Compiler: GCC {environment['compiler']}; kernel: {environment['uname']}.
- Seven measured primary repetitions per dataset/method after one verified warm-up. Shuffle datasets with seed {environment['seed']}; alternate method order within each round. Complete-file validation uses three measured repetitions after one warm-up. The signing/compression batch uses five measured repetitions after one warm-up.
- Time with `CLOCK_MONOTONIC` around the actual operation only; CPU is user plus system time from `getrusage`. Setup, input copies, process/configuration startup, and subsequent verification are outside timed intervals.
- Warm-cache, buffered-I/O benchmark on the VM's native filesystem. No `fsync`, no host-wide cache dropping, no enforced CPU frequency, and no simultaneous compilation/collection. Kernel writeback from untimed copies can overlap later work; CPU time is reported separately. It is not a cold-storage or crash-durability benchmark.
- Peak RSS uses Linux `/proc/self/status` VmHWM of the executed driver, including shared-library/configuration startup. An idle startup floor is shown. This avoids inherited Python pre-exec RSS and does not claim exclusive codec allocation size. These are benchmark-driver RSS values, not the full manager daemon footprint.
- Decompression uses a separate common 64 KiB streaming readback harness against the same libraries and writes restored bytes to disk; this is not an existing manager decompression path. Exact SHA-256 verification follows outside timing.
- Production-batch timing calls `manage_files()` over a fixture containing all 21 files as base/numbered rotations. It includes existing checksum generation and compression, but excludes daemon startup, the day-wait delay, unrelated housekeeping, and fixture setup. It is a corpus batch, not a claim about one actual day's elapsed rotation time.

## Variability and uncertainty

Use per-file medians; aggregate throughput divides total raw bytes by the sum of those medians. The plots retain the observed timing distributions. A paired bootstrap over the seven day clusters (10,000 resamples, fixed seed) gives a descriptive within-week interval of **{intervals[0,0]:.2f}% to {intervals[1,0]:.2f}%** for sample output reduction and **{intervals[0,1]:.2f}× to {intervals[1,1]:.2f}×** for compression speedup. These intervals reflect day-composition variability using median timings, not population-level confidence across Wazuh installations or a complete model of host noise.

All verification flags are true. There are {sum(not r['warmup'] and r['operation']=='compress' for r in all_rows)} measured per-file compressions, {sum(not r['warmup'] and r['operation']=='decompress' for r in all_rows)} measured readbacks, and {len(daily)} measured production batches, plus excluded verified warm-ups.

## Implications and limits

Keep gzip as the compatibility default. Offer zstd as an opt-in choice for environments whose downstream readers support `.zst`. Assess the CPU, memory, and disk-space plots together rather than assuming every metric improves. This study concerns alert/archive storage compression in `wazuh-monitord`, not `remoted` network traffic, agent transport, or indexer compression.

One supervision server and one benchmark host cannot characterize every workload, hardware platform, or storage backend. The study does not measure cold-disk throughput, distributed clusters, concurrent-manager load, prolonged thermal effects, crash recovery, or a compression-level tuning sweep. Small/empty files and high-entropy payloads are not separately characterized for performance. The private corpus cannot be publicly redistributed; its anonymous manifest, hashes, measured rows, build metadata, and reproducible harness accompany the report. Larger independent workloads would strengthen generalization.

## Reproduction and supporting data

See `README.md` beside the benchmark source for build/run commands. `measured-trials.csv` contains every measured observation; `per-file-medians.csv`, `category-summary.csv`, and `comparisons.csv` contain derived tables. `environment.json` and `corpus-manifest.json` record versions, input sizes, segment offsets, and hashes without source identifiers. PNG and SVG figures are provided for export.
"""
    markdown = text + "\n## Figures\n\n" + "\n\n".join(
        f"![{caption}]({name}.png)\n\n{caption}" for name, caption in figures)
    (output/"REPORT.md").write_text(markdown)
    for source, name in ((args.primary / "trials.jsonl", "primary-trials.jsonl"),
                         (args.full / "trials.jsonl", "full-validation-trials.jsonl"),
                         (args.full / "environment.json", "full-validation-environment.json")):
        (output / name).write_bytes(source.read_bytes())
    # Keep the HTML standalone; use semantic sections and embedded PNGs.
    def paragraph_markup(value):
        escaped = html.escape(value)
        escaped = re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", escaped)
        return re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    fragments=[]
    lines=text.splitlines();i=0
    while i<len(lines):
        line=lines[i]
        if line.startswith("# "):
            fragments.append("<h1>"+paragraph_markup(line[2:])+"</h1>")
        elif line.startswith("## "):
            fragments.append("<h2>"+paragraph_markup(line[3:])+"</h2>")
        elif line.startswith("| "):
            table=[]
            while i<len(lines) and lines[i].startswith("|"):
                table.append(lines[i]);i+=1
            fragments.append("<table><thead><tr>"+"".join("<th>"+html.escape(c.strip())+"</th>" for c in table[0].strip("|").split("|"))+"</tr></thead><tbody>"+
                             "".join("<tr>"+"".join("<td>"+html.escape(c.strip())+"</td>" for c in row.strip("|").split("|"))+"</tr>" for row in table[2:])+"</tbody></table>")
            continue
        elif line.startswith("- "):
            fragments.append("<p class='method'>"+paragraph_markup(line[2:])+"</p>")
        elif line:
            fragments.append("<p>"+paragraph_markup(line)+"</p>")
        i+=1
    figure_markup=[]
    for name,caption in figures:
        encoded=base64.b64encode((output/f"{name}.png").read_bytes()).decode()
        figure_markup.append(f'<figure><img src="data:image/png;base64,{encoded}" alt="{html.escape(caption)}"><figcaption>{html.escape(caption)}</figcaption></figure>')
    insertion=fragments.index('<h2>Complete archive cross-check</h2>')
    fragments[insertion:insertion]=figure_markup[:5]
    insertion=fragments.index('<h2>Measurement protocol</h2>')
    fragments[insertion:insertion]=figure_markup[5:]
    document='''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Wazuh gzip versus zstd — real-log benchmark</title><style>
body{font:16px/1.65 system-ui,sans-serif;color:#26313a;background:#edf0f2;margin:0}main{max-width:1120px;margin:36px auto;padding:48px;background:white}h1{font-size:34px;line-height:1.2;max-width:850px}h2{margin-top:40px;font-size:23px}code{font-size:.9em;background:#f0f3f5;padding:2px 4px;border-radius:3px}p{max-width:1000px}table{border-collapse:collapse;width:100%;font-size:14px;margin:24px 0}th,td{padding:10px 12px;border-bottom:1px solid #dce2e5;text-align:right}th:first-child,td:first-child{text-align:left}th{background:#f3f6f7}figure{margin:36px 0}img{width:100%;height:auto}figcaption{color:#58656f;font-size:14px}.method{padding-left:16px;border-left:3px solid #d5e3e9}@media print{body{background:white}main{margin:0;padding:0}figure,table{break-inside:avoid}}@media(max-width:700px){main{margin:0;padding:20px}table{font-size:12px}th,td{padding:6px}}
</style><main>'''+"\n".join(fragments)+"</main></html>"
    (output/"REPORT.html").write_text(document)
    (output/"summary.json").write_text(json.dumps(dict(primary=summary,improvements=improvements,full_files=full_files,
                                                      daily={a:median(r['wall_s'] for r in daily if r['algorithm']==a) for a in COLORS},
                                                      bootstrap_95=intervals.tolist()),indent=2)+"\n")
    print(json.dumps({"sample_output_reduction_pct":saving,"sample_compression_speedup":speedup,
                      "daily_speedup":daily_g/daily_z,"full_archive_output_reduction_pct":100*(1-full_z['compressed_bytes']/full_g['compressed_bytes']),
                      "full_archive_speedup":full_g['compression_wall_s']/full_z['compression_wall_s']},indent=2))


if __name__=="__main__":
    main()
