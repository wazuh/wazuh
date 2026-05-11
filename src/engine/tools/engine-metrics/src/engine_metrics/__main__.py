#!/usr/bin/env python3
"""
engine-metrics: Real-time metrics dashboard and CLI for Wazuh Engine.

Subcommands:
    dashboard   Start the real-time web dashboard
    plot        Generate a static HTML report from a log file
    dump        Dump all metrics via engine API
    list        List all registered metric names
    get         Get a single metric value
    enable      Enable a metric
    disable     Disable a metric
"""

import sys
import argparse
from importlib.metadata import metadata

from engine_metrics.cmds.dashboard import configure as configure_dashboard
from engine_metrics.cmds.plot import configure as configure_plot
from engine_metrics.cmds.dump import configure as configure_dump
from engine_metrics.cmds.list import configure as configure_list
from engine_metrics.cmds.get import configure as configure_get
from engine_metrics.cmds.enable import configure_enable, configure_disable


def parse_args():
    meta = metadata('engine-metrics')
    parser = argparse.ArgumentParser(
        prog='engine-metrics',
        description='Metrics dashboard and CLI tools for Wazuh Engine'
    )
    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f'%(prog)s {meta.get("Version")}'
    )

    subparsers = parser.add_subparsers(
        title='subcommands',
        required=True,
        dest='subcommand'
    )

    configure_dashboard(subparsers)
    configure_plot(subparsers)
    configure_dump(subparsers)
    configure_list(subparsers)
    configure_get(subparsers)
    configure_enable(subparsers)
    configure_disable(subparsers)

    return parser.parse_args()


def main():
    args = parse_args()
    args.func(vars(args))


if __name__ == '__main__':
    sys.exit(main())
