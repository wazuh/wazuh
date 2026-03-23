#! /usr/bin/env python3
# November 7, 2023

# Analyze the CSV files from performance tests and give CPU & RSS stats
# Usage: csv-stat.py <DAEMON> <FILE>

import csv
import sys
import argparse

QUANTUM = 5


def parse_args():
    parser = argparse.ArgumentParser(
        description='Analyze CSV files from performance tests and give CPU & RSS stats.',
        epilog='DAEMON: name of the process to filter\nFILE: input CSV file'
    )
    parser.add_argument('daemon', help='Process name to filter')
    parser.add_argument('file', help='Input CSV file')
    return parser.parse_args()


def get_data(reader, daemon):
    cpu_sum = 0.0
    cpu_max = 0.0
    rss_sum = 0.0
    rss_max = 0.0
    count = 0

    for row in reader:
        if row[3] == daemon:
            cpu = float(row[4])
            rss = float(row[5])

            cpu_sum += cpu
            rss_sum += rss
            count += 1

            cpu_max = max(cpu_max, cpu)
            rss_max = max(rss_max, rss)

    return cpu_sum, cpu_max, rss_sum, rss_max, count


def print_results(cpu_sum, cpu_max, rss_sum, rss_max, count):
    print('CPU:')
    print(f'  Sum: {(cpu_sum / 100 * QUANTUM):.2f} sec.')
    print(
        f'  Avg: {(cpu_sum * QUANTUM / count):.2f} %' if count else '  Avg: N/A')
    print(f'  Max: {cpu_max:.2f} %')
    print('RSS:')
    print(f'  Avg: {(rss_sum / count):.2f} KiB' if count else '  Avg: N/A')
    print(f'  Max: {rss_max:.2f} KiB')


def main():
    args = parse_args()
    try:
        with open(args.file) as f:
            reader = csv.reader(f)
            cpu_sum, cpu_max, rss_sum, rss_max, count = get_data(
                reader, args.daemon)
        print_results(cpu_sum, cpu_max, rss_sum, rss_max, count)
    except FileNotFoundError:
        print(f'Error: File {args.file} not found.')
        sys.exit(1)
    except Exception as e:
        print(f'Error: {e}')
        sys.exit(1)


if __name__ == '__main__':
    main()
