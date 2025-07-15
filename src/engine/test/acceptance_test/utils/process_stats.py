#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import matplotlib.pyplot as plt
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

def plot_metrics(timestamps, metrics, labels, title, ylabel, filename):
    plt.figure(figsize=(12, 6))
    for metric, label in zip(metrics, labels):
        plt.plot(timestamps, metric, label=label)
    plt.title(title)
    plt.xlabel('Timestamp')
    plt.ylabel(ylabel)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()

def plot_combined_metrics(timestamps, metrics_dict, title, filename):
    plt.figure(figsize=(12, 8))
    
    for i, (name, metric) in enumerate(metrics_dict.items(), 1):
        plt.subplot(len(metrics_dict), 1, i)
        plt.plot(timestamps, metric)
        plt.title(name)
        plt.xlabel('Timestamp')
        plt.ylabel(name)
        plt.grid(True)
    
    plt.tight_layout()
    plt.suptitle(title, y=1.02)
    plt.savefig(filename)
    plt.close()

def process_data(file_path, process_name):
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

    # Generate plots
    plot_metrics(timestamp, [readOPS, writeOPS], ['Read OPS', 'Write OPS'], 
                f'{process_name} - Read/Write Operations', 'Operations per second', 
                f'{process_name.lower()}_io_ops.png')

    plot_metrics(timestamp, [cpuPCT], ['CPU Usage'], 
                f'{process_name} - CPU Usage', 'CPU Percentage', 
                f'{process_name.lower()}_cpu.png')

    other_metrics = {
        'RSS Memory': rssKB,
        'VMS Memory': vmsKB,
        'File Descriptors': fd,
        'Disk Usage': diskPCT,
        'USS Memory': ussKB,
        'PSS Memory': pssKB,
        'Swap Memory': swapKB
    }

    plot_combined_metrics(timestamp, other_metrics, 
                         f'{process_name} - Other Metrics', 
                         f'{process_name.lower()}_other_metrics.png')

def main():
    # Arguments parsing
    arg_parser = ArgumentParser()
    arg_parser.add_argument("-e", "--engine", help="Engine test output file path")
    arg_parser.add_argument("-a", "--analysisd", help="Analysisd test output file path")
    args = arg_parser.parse_args()

    if args.analysisd:
        process_data(args.analysisd, "ANALYSISD")

    if args.analysisd and args.engine:
        print("------------------------------------------------------------------")

    if args.engine:
        process_data(args.engine, "ENGINE")

    print("")

if __name__ == "__main__":
    main()