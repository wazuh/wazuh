#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

def main():
    # Arguments parsing
    arg_parser = ArgumentParser()
    arg_parser.add_argument("-e", "--engine", help="Engine test output file path")
    arg_parser.add_argument("-a", "--analysisd", help="Analysisd test output file path")
    args = arg_parser.parse_args()

    column_headers = ["TIMESTAMP", "PROCESS", "CPU_PCT", "RSS_KB", "VMS_KB", "FD", "READ_OPS",
                      "WRITE_OPS", "DISK_READ_B", "DISK_WRITTEN_B", "DISK_PCT", "USS_KB", "PSS_KB", "SWAP_KB"]

    if args.analysisd:

        data = read_csv(args.analysisd, usecols=column_headers)

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

        print("")
        print("** ANALYSISD stats")
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

    if args.analysisd and args.engine:

        print("------------------------------------------------------------------")

    if args.engine:

        data = read_csv(args.engine, usecols=column_headers)

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

        print("")
        print("** ENGINE stats")
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

if __name__ == "__main__":
    main()
