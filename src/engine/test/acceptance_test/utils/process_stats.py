#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import matplotlib.pyplot as plt
import numpy as np
from pandas import read_csv
from statistics import median
from argparse import ArgumentParser

def average(List):
    return sum(List) / len(List)

# Most frequent element
def mode(List):
    counter = 0
    num = List[0]

    for item in List:
        curr_frequency = List.count(item)
        if(curr_frequency> counter):
            counter = curr_frequency
            num = item

    return num

def list_print_stats(List, listName):
    print("{} minimum: {:.2f}".format(listName, min(List)))
    print("{} maximum: {:.2f}".format(listName, max(List)))
    print("{} average: {:.2f}".format(listName, average(List)))
    print("{} median: {:.2f}".format(listName, median(List)))
    print("{} mode: {:.2f}".format(listName, mode(List)))

def plot_combined_metrics(timestamps, metrics_dict, title, filename):
    plt.figure(figsize=(12, 12))

    # Memory metrics subplot with different line styles and markers
    ax1 = plt.subplot(3, 1, 1)
    memory_metrics = metrics_dict['memory']

    # Define line styles and markers for each memory metric
    styles = {
        'RSS': {'color': 'blue', 'linestyle': '-', 'marker': 'o', 'markersize': 2},
        'VMS': {'color': 'green', 'linestyle': '--', 'marker': 's', 'markersize': 2},
        'USS': {'color': 'red', 'linestyle': '-.', 'marker': '^', 'markersize': 2},
        'PSS': {'color': 'purple', 'linestyle': ':', 'marker': 'D', 'markersize': 2}
    }

    for name, metric in memory_metrics.items():
        if name in styles:
            ax1.plot(timestamps, metric, label=name,
                    linestyle=styles[name]['linestyle'],
                    color=styles[name]['color'],
                    marker=styles[name]['marker'],
                    markersize=styles[name]['markersize'],
                    linewidth=2)

    ax1.set_title('Memory Metrics (KB)')
    ax1.set_ylabel('KB')
    ax1.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    ax1.grid(True)

    # CPU and Disk metrics subplot with smoothing
    ax2 = plt.subplot(3, 1, 2)

    # Smoothing function
    def smooth(y, box_pts=3):
        box = np.ones(box_pts)/box_pts
        y_smooth = np.convolve(y, box, mode='same')
        return y_smooth

    # Define styles for CPU/Disk metrics
    cpu_disk_styles = {
        'CPU %': {'color': 'red', 'linestyle': '-', 'marker': ''},
        'Disk %': {'color': 'blue', 'linestyle': '--', 'marker': ''},
        'FD Count': {'color': 'green', 'linestyle': '-.', 'marker': ''}
    }

    for name, metric in metrics_dict['cpu_disk'].items():
        smoothed = smooth(metric)
        ax2.plot(timestamps, smoothed,
                label=f'{name} (smoothed)',
                linestyle=cpu_disk_styles[name]['linestyle'],
                color=cpu_disk_styles[name]['color'],
                linewidth=2)

    ax2.set_title('CPU and Disk Metrics (Smoothed)')
    ax2.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    ax2.grid(True)

    # IO Operations subplot
    ax3 = plt.subplot(3, 1, 3)
    io_styles = {
        'Read OPS': {'color': 'orange', 'linestyle': '-', 'marker': ''},
        'Write OPS': {'color': 'brown', 'linestyle': '-', 'marker': ''}
    }

    for name, metric in metrics_dict['io'].items():
        ax3.plot(timestamps, metric, label=name,
                linestyle=io_styles[name]['linestyle'],
                color=io_styles[name]['color'],
                marker=io_styles[name]['marker'],
                markersize=4,
                linewidth=2)

    ax3.set_title('IO Operations')
    ax3.set_xlabel('Time (simplified)')
    ax3.set_ylabel('Operations per second')
    ax3.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    ax3.grid(True)

    # Adjust x-axis for all subplots
    for ax in [ax1, ax2, ax3]:
        ax.xaxis.set_major_locator(plt.MaxNLocator(6))
        ax.set_xticklabels([f"{x:.0f}" for x in ax.get_xticks()])

    plt.tight_layout()
    plt.subplots_adjust(right=0.8, hspace=0.4)  # Adjust spacing
    plt.suptitle(title, y=1.02, fontsize=12)
    plt.savefig(filename, bbox_inches='tight', dpi=300)
    plt.close()

def process_data(file_path, process_name, plot_enabled):
    column_headers = ["TIMESTAMP", "PROCESS", "CPU_PCT", "RSS_KB", "VMS_KB", "FD", "READ_OPS",
                      "WRITE_OPS", "DISK_READ_B", "DISK_WRITTEN_B", "DISK_PCT", "USS_KB", "PSS_KB", "SWAP_KB"]

    data = read_csv(file_path, usecols=column_headers)

    timestamp = data["TIMESTAMP"].tolist()
    process = data["PROCESS"].tolist()
    cpuPCT = data["CPU_PCT"].tolist()
    rssKB = data["RSS_KB"].tolist()
    vmsKB = data["VMS_KB"].tolist()
    fd = data["FD"].tolist()
    readOPS = data["READ_OPS"].tolist()
    writeOPS = data["WRITE_OPS"].tolist()
    diskReadB = data["DISK_READ_B"].tolist()
    diskWrittenB = data["DISK_WRITTEN_B"].tolist()
    diskPCT = data["DISK_PCT"].tolist()
    ussKB = data["USS_KB"].tolist()
    pssKB = data["PSS_KB"].tolist()
    swapKB = data["SWAP_KB"].tolist()

    # Print stats
    print("")
    print(f"** {process_name} stats")
    print("")
    list_print_stats(cpuPCT, "CPU_PCT")
    print("")
    list_print_stats(rssKB, "RSS_KB")
    print("")
    list_print_stats(vmsKB, "VMS_KB")
    print("")
    list_print_stats(fd, "FD")
    print("")
    list_print_stats(readOPS, "READ_OPS")
    print("")
    list_print_stats(writeOPS, "WRITE_OPS")
    print("")
    list_print_stats(diskReadB, "DISK_READ_B")
    print("")
    list_print_stats(diskWrittenB, "DISK_WRITTEN_B")
    print("")
    list_print_stats(diskPCT, "DISK_PCT")
    print("")
    list_print_stats(ussKB, "USS_KB")
    print("")
    list_print_stats(pssKB, "PSS_KB")
    print("")
    list_print_stats(swapKB, "SWAP_KB")
    print("")

    if plot_enabled:
        # Group metrics for plotting
        metrics_dict = {
            'memory': {
                'RSS': rssKB,
                'VMS': vmsKB,
                'USS': ussKB,
                'PSS': pssKB
            },
            'cpu_disk': {
                'CPU %': cpuPCT,
                'Disk %': diskPCT,
                'FD Count': fd
            },
            'io': {
                'Read OPS': readOPS,
                'Write OPS': writeOPS
            }
        }

        plot_combined_metrics(timestamp, metrics_dict,
                            f'{process_name} - Performance Metrics',
                            f'{process_name.lower()}_metrics.png')

def main():
    # Arguments parsing
    arg_parser = ArgumentParser()
    arg_parser.add_argument("-e", "--engine", help="Engine test output file path")
    arg_parser.add_argument("-a", "--analysisd", help="Analysisd test output file path")
    arg_parser.add_argument("--no-plots", action='store_true', help="Disable plotting")
    args = arg_parser.parse_args()

    plot_enabled = not args.no_plots

    if args.analysisd:
        process_data(args.analysisd, "ANALYSISD", plot_enabled)

    if args.analysisd and args.engine:
        print("------------------------------------------------------------------")

    if args.engine:
        process_data(args.engine, "ENGINE", plot_enabled)

    print("")

if __name__ == "__main__":
    main()