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
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class WazuhHelpFormatter(argparse.ArgumentParser):
    def format_help(self):
        msg = """
{0} --help | --sync [-t Node1 NodeN] [--debug] | --list-files [-t Node1 NodeN] [-f File1 FileN] [--debug] | --list-agents [--debug] | --list-nodes [-t Node1 NodeN] [--debug]

Usage:
\t-h, --help                                  # Show this help message
\t-s, --sync                                  # Force the nodes to initiate the synchronization process
\t-l, --list-files                            # List the file status for every node
\t-a, --list-agents                           # List agents
\t-n, --list-nodes                            # List nodes

Filters:
\t -t, --filter-node                          # Filter by node
\t -f, --filter-file                          # Filter by file

Others:
\t     --debug                                 # Show debug information

""".format(basename(argv[0]))
        return msg
    def error(self, message):
        print("Wrong arguments: {0}".format(message))
        self.print_help()
        exit(1)

parser=WazuhHelpFormatter(usage='custom usage')
parser._positionals.title = 'Wazuh Cluster control interface'

parser.add_argument('-t', '--filter-node', dest='filter_node', nargs='*', type=str, help="Node")
parser.add_argument('-f', '--filter-file', dest='filter_file', nargs='*', type=str, help="File")
parser.add_argument('--debug', action='store_const', const='debug', help="Enable debug mode")

exclusive = parser.add_mutually_exclusive_group()
exclusive.add_argument('-s', '--sync', const='sync', action='store_const', help="Force the nodes to initiate the synchronization process")
exclusive.add_argument('-l', '--list-files', const='list_files', action='store_const', help="List the file status for every node")
exclusive.add_argument('-a', '--list-agents', const='list_agents', action='store_const', help="List agents")
exclusive.add_argument('-n', '--list-nodes', const='list_nodes', action='store_const', help="List tnodes")

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


def _get_file_status(file_list, node_list):
    print("ToDo: Filters not implemented")

    file_status = req_file_status_to_clients()
    print(json.dumps(file_status, indent=4))

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

def _sync(node_list):
    if node_list:
        if type(node_list) is list:
            response = force_clients_to_start_sync(node_list)
        else:
            response = force_clients_to_start_sync([node_list])
    else:
        response = force_clients_to_start_sync()


    print(json.dumps(response, indent=4))

def signal_handler(n_signal, frame):
    exit(1)


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

        try:
            if args.sync is not None:
                _sync(args.filter_node)
            elif args.list_files is not None:
                _get_file_status(args.filter_file, args.filter_node)
            elif args.list_agents is not None:
                _get_agents_status()
            elif args.list_nodes is not None:
                _get_nodes_status(args.filter_node)
            else:
                parser.print_help()
                exit()
        except WazuhException as e:
            raise e

    except Exception as e:
        logging.error(str(e))
        if args.debug:
            raise
        exit(1)
