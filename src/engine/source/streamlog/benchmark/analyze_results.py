#!/usr/bin/env python3
"""
Script to analyze and visualize benchmark results from async_vs_sync_bench.cpp
"""

import re
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from typing import List, Dict, Tuple


def parse_benchmark_output(output: str) -> pd.DataFrame:
    """
    Parse the benchmark output and return a pandas DataFrame
    """
    lines = output.strip().split('\n')

    # Find the start of the benchmark results
    start_idx = 0
    for i, line in enumerate(lines):
        if line.startswith('BM_'):
            start_idx = i
            break

    data = []

    for line in lines[start_idx:]:
        if not line.startswith('BM_'):
            continue

        # Parse the benchmark line
        # Format: BM_TestName/threads/events/manual_time    time_ns    cpu_ns    iterations    items_per_second=value
        parts = line.split()
        if len(parts) < 5:
            continue

        # Extract benchmark name and parameters
        name_part = parts[0]
        name_match = re.match(r'(BM_\w+)/(\d+)/(\d+)/manual_time', name_part)
        if not name_match:
            continue

        benchmark_name = name_match.group(1)
        threads = int(name_match.group(2))
        events_per_thread = int(name_match.group(3))
        total_events = threads * events_per_thread

        # Extract time (remove 'ns' suffix)
        time_ns = int(parts[1])

        # Extract throughput (items per second)
        throughput_part = parts[-1]  # items_per_second=value
        throughput_match = re.search(r'items_per_second=([0-9.]+)([kM])?/s', throughput_part)
        if throughput_match:
            value = float(throughput_match.group(1))
            unit = throughput_match.group(2)
            if unit == 'k':
                throughput = value * 1000
            elif unit == 'M':
                throughput = value * 1000000
            else:
                throughput = value
        else:
            throughput = 0

        # Categorize the benchmark
        if 'SyncMultiThreadWithFlush' in benchmark_name:
            category = 'Sync Multi-Thread (Flush)'
        elif 'SyncMultiThreadWithoutFlush' in benchmark_name:
            category = 'Sync Multi-Thread (No Flush)'
        elif 'AsyncDedicatedWriterWithFlush' in benchmark_name:
            category = 'Async Dedicated Writer (Flush)'
        elif 'AsyncDedicatedWriterWithoutFlush' in benchmark_name:
            category = 'Async Dedicated Writer (No Flush)'
        else:
            category = 'Unknown'

        data.append({
            'benchmark': benchmark_name,
            'category': category,
            'threads': threads,
            'events_per_thread': events_per_thread,
            'total_events': total_events,
            'time_ns': time_ns,
            'time_ms': time_ns / 1_000_000,
            'throughput_per_sec': throughput,
            'latency_us_per_event': (time_ns / 1000) / total_events
        })

    return pd.DataFrame(data)


def create_visualizations(df: pd.DataFrame):
    """
    Create various visualizations of the benchmark results
    """
    # Set up the plotting style
    plt.style.use('seaborn-v0_8')
    fig = plt.figure(figsize=(20, 15))

    # Color mapping for different categories
    colors = {
        'Sync Multi-Thread (Flush)': '#FF6B6B',
        'Sync Multi-Thread (No Flush)': '#4ECDC4',
        'Async Dedicated Writer (Flush)': '#45B7D1',
        'Async Dedicated Writer (No Flush)': '#96CEB4'
    }

    # 1. Throughput vs Thread Count
    plt.subplot(2, 3, 1)
    for category in df['category'].unique():
        cat_data = df[df['category'] == category]
        plt.plot(cat_data['threads'], cat_data['throughput_per_sec'] / 1000,
                 marker='o', linewidth=2, label=category, color=colors.get(category, 'gray'))

    plt.xlabel('Number of Threads')
    plt.ylabel('Throughput (k events/sec)')
    plt.title('Throughput vs Thread Count')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True, alpha=0.3)
    plt.xscale('log', base=2)

    # 2. Execution Time vs Thread Count
    plt.subplot(2, 3, 2)
    for category in df['category'].unique():
        cat_data = df[df['category'] == category]
        plt.plot(cat_data['threads'], cat_data['time_ms'],
                 marker='s', linewidth=2, label=category, color=colors.get(category, 'gray'))

    plt.xlabel('Number of Threads')
    plt.ylabel('Execution Time (ms)')
    plt.title('Execution Time vs Thread Count')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True, alpha=0.3)
    plt.xscale('log', base=2)

    # 3. Latency per Event vs Thread Count
    plt.subplot(2, 3, 3)
    for category in df['category'].unique():
        cat_data = df[df['category'] == category]
        plt.plot(cat_data['threads'], cat_data['latency_us_per_event'],
                 marker='^', linewidth=2, label=category, color=colors.get(category, 'gray'))

    plt.xlabel('Number of Threads')
    plt.ylabel('Latency per Event (μs)')
    plt.title('Latency per Event vs Thread Count')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True, alpha=0.3)
    plt.xscale('log', base=2)

    # 4. Throughput Comparison Bar Chart (at different thread counts)
    plt.subplot(2, 3, 4)
    thread_counts = [1, 2, 4, 8, 16, 32]
    width = 0.2
    x = np.arange(len(thread_counts))

    categories = df['category'].unique()
    for i, category in enumerate(categories):
        throughputs = []
        for tc in thread_counts:
            cat_data = df[(df['category'] == category) & (df['threads'] == tc)]
            if not cat_data.empty:
                throughputs.append(cat_data['throughput_per_sec'].iloc[0] / 1000)
            else:
                throughputs.append(0)

        plt.bar(x + i * width, throughputs, width, label=category,
                color=colors.get(category, 'gray'), alpha=0.8)

    plt.xlabel('Number of Threads')
    plt.ylabel('Throughput (k events/sec)')
    plt.title('Throughput Comparison by Thread Count')
    plt.xticks(x + width * 1.5, thread_counts)
    plt.legend()
    plt.grid(True, alpha=0.3, axis='y')

    # 5. Flush vs No Flush Comparison
    plt.subplot(2, 3, 5)
    sync_flush = df[df['category'] == 'Sync Multi-Thread (Flush)']
    sync_no_flush = df[df['category'] == 'Sync Multi-Thread (No Flush)']
    async_flush = df[df['category'] == 'Async Dedicated Writer (Flush)']
    async_no_flush = df[df['category'] == 'Async Dedicated Writer (No Flush)']

    plt.plot(sync_flush['threads'], sync_flush['throughput_per_sec'] / 1000,
             'r-o', label='Sync (Flush)', linewidth=2)
    plt.plot(sync_no_flush['threads'], sync_no_flush['throughput_per_sec'] / 1000,
             'r--s', label='Sync (No Flush)', linewidth=2)
    plt.plot(async_flush['threads'], async_flush['throughput_per_sec'] / 1000,
             'b-o', label='Async (Flush)', linewidth=2)
    plt.plot(async_no_flush['threads'], async_no_flush['throughput_per_sec'] / 1000,
             'b--s', label='Async (No Flush)', linewidth=2)

    plt.xlabel('Number of Threads')
    plt.ylabel('Throughput (k events/sec)')
    plt.title('Flush vs No Flush Impact')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.xscale('log', base=2)

    # 6. Speedup Analysis
    plt.subplot(2, 3, 6)
    # Calculate speedup relative to single-threaded performance
    for category in df['category'].unique():
        cat_data = df[df['category'] == category].sort_values('threads')
        if not cat_data.empty:
            baseline_throughput = cat_data[cat_data['threads'] == 1]['throughput_per_sec'].iloc[0]
            speedup = cat_data['throughput_per_sec'] / baseline_throughput
            plt.plot(cat_data['threads'], speedup, marker='o', linewidth=2,
                     label=category, color=colors.get(category, 'gray'))

    # Add ideal speedup line
    threads = [1, 2, 4, 8, 16, 32]
    plt.plot(threads, threads, 'k--', alpha=0.5, label='Ideal Speedup')

    plt.xlabel('Number of Threads')
    plt.ylabel('Speedup Factor')
    plt.title('Speedup Analysis')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.xscale('log', base=2)
    plt.yscale('log', base=2)

    plt.tight_layout()
    plt.savefig('/tmp/benchmark_analysis.png', dpi=300, bbox_inches='tight')
    plt.show()


def print_summary_statistics(df: pd.DataFrame):
    """
    Print summary statistics from the benchmark results
    """
    print("=" * 80)
    print("BENCHMARK SUMMARY STATISTICS")
    print("=" * 80)

    # Best performing configurations
    print("\n📊 BEST PERFORMANCE BY CATEGORY:")
    print("-" * 50)
    for category in df['category'].unique():
        cat_data = df[df['category'] == category]
        best = cat_data.loc[cat_data['throughput_per_sec'].idxmax()]
        print(f"{category}:")
        print(f"  • Best: {best['threads']} threads - {best['throughput_per_sec']/1000:.1f}k events/sec")
        print(f"  • Latency: {best['latency_us_per_event']:.2f} μs/event")
        print()

    # Overall best performance
    overall_best = df.loc[df['throughput_per_sec'].idxmax()]
    print(f"🏆 OVERALL BEST PERFORMANCE:")
    print(f"  • Configuration: {overall_best['category']} with {overall_best['threads']} threads")
    print(f"  • Throughput: {overall_best['throughput_per_sec']/1000:.1f}k events/sec")
    print(f"  • Latency: {overall_best['latency_us_per_event']:.2f} μs/event")
    print()

    # Flush impact analysis
    print("💾 FLUSH IMPACT ANALYSIS:")
    print("-" * 30)
    sync_flush_avg = df[df['category'] == 'Sync Multi-Thread (Flush)']['throughput_per_sec'].mean()
    sync_no_flush_avg = df[df['category'] == 'Sync Multi-Thread (No Flush)']['throughput_per_sec'].mean()
    async_flush_avg = df[df['category'] == 'Async Dedicated Writer (Flush)']['throughput_per_sec'].mean()
    async_no_flush_avg = df[df['category'] == 'Async Dedicated Writer (No Flush)']['throughput_per_sec'].mean()

    sync_flush_impact = ((sync_no_flush_avg - sync_flush_avg) / sync_flush_avg) * 100
    async_flush_impact = ((async_no_flush_avg - async_flush_avg) / async_flush_avg) * 100

    print(f"  • Sync: No-flush is {sync_flush_impact:.1f}% faster than flush")
    print(f"  • Async: No-flush is {async_flush_impact:.1f}% faster than flush")
    print()

    # Async vs Sync comparison
    print("⚡ ASYNC vs SYNC COMPARISON:")
    print("-" * 35)
    sync_avg = df[df['category'].str.startswith('Sync')]['throughput_per_sec'].mean()
    async_avg = df[df['category'].str.startswith('Async')]['throughput_per_sec'].mean()
    improvement = ((async_avg - sync_avg) / sync_avg) * 100

    print(f"  • Sync average: {sync_avg/1000:.1f}k events/sec")
    print(f"  • Async average: {async_avg/1000:.1f}k events/sec")
    print(f"  • Async is {improvement:.1f}% faster than Sync on average")


def main():
    """
    Main function to run the analysis
    """
    # Benchmark output data
    benchmark_output = """
BM_SyncMultiThreadWithFlush/1/100000/manual_time          181093250 ns      3606016 ns            4 items_per_second=552.202k/s
BM_SyncMultiThreadWithFlush/2/50000/manual_time           226247333 ns      3578711 ns            3 items_per_second=441.994k/s
BM_SyncMultiThreadWithFlush/4/25000/manual_time           291865000 ns      2820322 ns            2 items_per_second=342.624k/s
BM_SyncMultiThreadWithFlush/8/12500/manual_time           312059000 ns      3140885 ns            2 items_per_second=320.452k/s
BM_SyncMultiThreadWithFlush/16/6250/manual_time           611303000 ns       663376 ns            1 items_per_second=163.585k/s
BM_SyncMultiThreadWithFlush/32/3125/manual_time           631545000 ns      1220197 ns            1 items_per_second=158.342k/s
BM_SyncMultiThreadWithoutFlush/1/100000/manual_time       185037250 ns      4903041 ns            4 items_per_second=540.432k/s
BM_SyncMultiThreadWithoutFlush/2/50000/manual_time        236136000 ns      3190721 ns            3 items_per_second=423.485k/s
BM_SyncMultiThreadWithoutFlush/4/25000/manual_time        276510500 ns      2398262 ns            2 items_per_second=361.65k/s
BM_SyncMultiThreadWithoutFlush/8/12500/manual_time        357347500 ns      3651517 ns            2 items_per_second=279.84k/s
BM_SyncMultiThreadWithoutFlush/16/6250/manual_time        626672000 ns       702955 ns            1 items_per_second=159.573k/s
BM_SyncMultiThreadWithoutFlush/32/3125/manual_time        648979000 ns      1226675 ns            1 items_per_second=154.088k/s
BM_AsyncDedicatedWriterWithFlush/1/100000/manual_time      96357429 ns      8701524 ns            7 items_per_second=1037.8k/s
BM_AsyncDedicatedWriterWithFlush/2/50000/manual_time       73849667 ns      8898078 ns            9 items_per_second=1.3541M/s
BM_AsyncDedicatedWriterWithFlush/4/25000/manual_time       82225000 ns      8640440 ns            9 items_per_second=1.21618M/s
BM_AsyncDedicatedWriterWithFlush/8/12500/manual_time       78184556 ns      9240360 ns            9 items_per_second=1.27902M/s
BM_AsyncDedicatedWriterWithFlush/16/6250/manual_time       86069444 ns     10387423 ns            9 items_per_second=1.16185M/s
BM_AsyncDedicatedWriterWithFlush/32/3125/manual_time       95542286 ns      9396873 ns            7 items_per_second=1046.66k/s
BM_AsyncDedicatedWriterWithoutFlush/1/100000/manual_time   86841625 ns      8358890 ns            8 items_per_second=1.15152M/s
BM_AsyncDedicatedWriterWithoutFlush/2/50000/manual_time    51346000 ns      8542054 ns           12 items_per_second=1.94757M/s
BM_AsyncDedicatedWriterWithoutFlush/4/25000/manual_time    61803667 ns      9017903 ns           12 items_per_second=1.61803M/s
BM_AsyncDedicatedWriterWithoutFlush/8/12500/manual_time    58767308 ns      9342549 ns           13 items_per_second=1.70163M/s
BM_AsyncDedicatedWriterWithoutFlush/16/6250/manual_time    54897000 ns      9154467 ns           13 items_per_second=1.82159M/s
BM_AsyncDedicatedWriterWithoutFlush/32/3125/manual_time    69677444 ns     10007337 ns            9 items_per_second=1.43518M/s
    """

    # Parse the data
    print("🔍 Parsing benchmark results...")
    df = parse_benchmark_output(benchmark_output)

    if df.empty:
        print("❌ No valid benchmark data found!")
        return

    print(f"✅ Successfully parsed {len(df)} benchmark results")

    # Print summary statistics
    print_summary_statistics(df)

    # Create visualizations
    print("\n📈 Generating visualizations...")
    create_visualizations(df)
    print("✅ Visualizations saved to /tmp/benchmark_analysis.png")

    # Save detailed results to CSV
    csv_path = "/tmp/benchmark_results.csv"
    df.to_csv(csv_path, index=False)
    print(f"📄 Detailed results saved to {csv_path}")


if __name__ == "__main__":
    main()
