#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from sys import path, argv, exit
from os.path import dirname, basename
import argparse
from itertools import chain
import logging
import socket
from signal import signal, SIGINT
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

class WazuhHelpFormatter(argparse.ArgumentParser):
    def format_help(self):
        msg = """
    {0} [-h] | [-d] | [-s] | [-p] | [-f  [-m MANAGER [MANAGER ...]]] | [-l [FILE [FILE ...]]] [-m MANAGER [MANAGER ...]]] | [-a [AGENT [AGENT ...]]] | [ -n [NODE [NODE ...]]] | [ --debug ]
    Usage:
\t-h                                  # Show this help message
\t-d                                  # Get last synchronization date and duration
\t
\t-s                                  # Scan for new files
\t-p                                  # Send all not synchronized files
\t-f -m MANAGER [MANAGER ...]         # Force synchronization of manager files
\t
\t-l                                  # List the status of all files
\t-l FILE [FILE ...]                  # List the status of specified files
\t-l -m MANAGER [MANAGER ...]         # List the status of all files of specified managers (name or IP)
\t
\t-a                                  # List the status of all agents
\t-a AGENT [AGENT ...]                # List the status of specified agents (IP)
\t
\t-n                                  # List nodes status
\t-n NODE [NODE ...]                  # List the status of specified nodes (name or IP)
    Params:
\t-h, --help
\t-d, --date
\t    --debug                         # Show debug information
\t
\t-s, --scan
\t-p, --push
\t-f, --force
\t
\t-l, --files
\t-a, --agents
\t-n, --nodes
""".format(basename(argv[0]))
        return msg
    def error(self, message):
        print("Wrong arguments: {0}".format(message))
        self.print_help()
        exit(1)

parser=WazuhHelpFormatter(usage='custom usage')
parser._positionals.title = 'Wazuh Cluster control interface'

parser.add_argument('-m', '--manager', dest='manager', nargs='*', type=str, help="List the status of the files of that manager")
parser.add_argument('--debug', action='store_const', const='debug', help="Enable debug mode")

exclusive = parser.add_mutually_exclusive_group()
exclusive.add_argument('-d', '--date', action='store_const', const='date', help="Get last synchronization date and duration")
exclusive.add_argument('-s', '--scan', const='scan', action='store_const', help="Scan for new files in the manager")
exclusive.add_argument('-p', '--push', const='push', action='store_const', help="Send all not synchronized files")
exclusive.add_argument('-f', '--force', const='force', action='store_const', help="Force synchronization of all files (use with -m to only force in one node)")
exclusive.add_argument('-l', '--files', metavar='FILE', dest='files', nargs='*', type=str, help="List the status of specified files (all if not specified)")
exclusive.add_argument('-a', '--agents', metavar='AGENT', dest='agents', nargs='*', type=bool, help="List all agents")
exclusive.add_argument('-n', '--nodes', metavar='NODE', dest='nodes', nargs='*', type=str, help="List the status of nodes (all if not specified)")

# Set framework path
path.append(dirname(argv[0]) + '/../framework')  # It is necessary to import Wazuh package

# Import framework
try:
    from wazuh import Wazuh
    from wazuh.cluster import *
    from wazuh.exception import WazuhException
except Exception as e:
    print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
    exit()

def pprint_table(data, headers, show_header=False):
    """
    Pretty print list of lists
    """
    def get_max_size_cols(l):
        """
        For each column of the table, return the size of the biggest element
        """
        return map(lambda x: max(map(lambda x: len(x)+2, x)), map(list, zip(*l)))

    if show_header:
        table = list(chain.from_iterable([[headers], data]))
    else:
        table = data

    sizes = get_max_size_cols(table)

    header_str = "{0}\n".format("-"*(sum(sizes)-2))
    table_str = header_str
    for row in table:
        for col, max_size in zip(row, sizes):
            table_str += "{0}{1}".format(col, " "*(max_size-len(col)))
        table_str += "\n"
        if show_header and row[0] == headers[0]:
            table_str += header_str
    table_str += header_str

    return table_str


def _get_file_status(file_list, manager):
    try:
        all_files = get_file_status_all_managers(file_list, manager)
    except socket.error as e:
        print("Error connecting to wazuh cluster service: {0}".format(str(e)))
        exit(1)

    print pprint_table(data=all_files, headers=["Manager","Filename","Status"], show_header=True)

def _get_agents_status():
    print pprint_table(data=get_agents_status(), headers=["ID", "IP", "Name", "Status", "Node name"], show_header=True)

def _get_nodes_status(node_list):
    logging.disable(logging.WARNING)
    all_nodes = get_nodes()

    if node_list:
        node_info = [[y['node'], y['url'], y['type'], y['status']] for y in all_nodes['items'] if y['node'] in node_list]
    else:
        node_info = [[x['node'], x['url'], x['type'], x['status']] for x in all_nodes['items']]

    print pprint_table(data=node_info, headers=["Node","Address","Type", "Status"], show_header=True)

def signal_handler(n_signal, frame):
    exit(1)

def _get_last_sync():
    date, duration = get_last_sync()

    print pprint_table(data=[[date, str(duration)]], headers=["Date", "Duration (s)"], show_header=True)

if __name__ == '__main__':
    # get arguments
    args = parser.parse_args()

    try:
        if args.debug:
            logging.getLogger('').setLevel(logging.DEBUG) #10

        # Initialize framework
        myWazuh = Wazuh(get_init=True)

        status = get_status_json()

        if status['enabled'] == 'no':
            raise WazuhException(3000, "The cluster is not enabled")
        elif status['running'] == 'no':
            raise WazuhException(3000, "The cluster is not running")

        if args.push:
            try:
                check_cluster_config(read_config())
            except WazuhException as e:
                raise e

            sync(debug=args.debug)

            logging.info("Synchronization successfully completed.")

        elif args.manager is not None and args.files is None and args.force is None:
            logging.error("Invalid argument: -m parameter requires -f (--force) or -l (--files)")

        elif args.files is not None:
            try:
                _get_file_status(args.files, args.manager)
            except WazuhException as e:
                raise e

        elif args.agents is not None:
            try:
                _get_agents_status()
            except WazuhException as e:
                raise e

        elif args.nodes is not None:
            _get_nodes_status(args.nodes)

        elif args.force is not None:
            try:
                check_cluster_config(read_config())
            except WazuhException as e:
                raise e

            if args.manager is None:
                sync(debug=args.debug, force=True)
            else:
                for node in args.manager:
                    sync_one_node(debug=args.debug, node=node, force=True)

            logging.info("Forced synchronization successfully completed.")

        elif args.scan is not None:
            try:
                scan_for_new_files()
                logging.info("Scan successfully completed.")
            except socket.error as e:
                raise e

        elif args.date is not None:
            try:
                _get_last_sync()
            except socket.error as e:
                raise e

        else:
            parser.print_help()
            exit()
    except Exception as e:
        logging.error(str(e))
        if args.debug:
            raise
        exit(1)
