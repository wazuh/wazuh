#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from sys import path, argv, exit
from os.path import dirname, basename
import argparse
from itertools import chain
import logging
import socket
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

parser = argparse.ArgumentParser(description="Wazuh Cluster control interface")

push_group = parser.add_argument_group('Push updates')
push_group.add_argument('-p', '--push', const='push', action='store_const', help="Send all not synchronized files")
push_group.add_argument('-f', '--force', const='force', action='store_const', help="Force synchronization of all files (use with -m to only force in one node)")

files_group = parser.add_argument_group('Retrieve file status')
files_group.add_argument('-l', '--files', metavar='FILE', dest='files', nargs='*', type=str, help="List the status of specified files (all if not specified)")
files_group.add_argument('-m', '--manager', dest='manager', nargs='*', type=str, help="List the status of the files of that manager")
files_group.add_argument('-s', '--scan', const='scan', action='store_const', help="Scan for new files in the manager")

agents_group = parser.add_argument_group('Retrieve agent status')
agents_group.add_argument('-a', '--agents', metavar='AGENT', dest='agents', nargs='*', type=bool, help="List all agents")

nodes_group = parser.add_argument_group('Retrieve node status')
nodes_group.add_argument('-n', '--nodes', metavar='NODE', dest='nodes', nargs='*', type=str, help="List the status of nodes (all if not specified)")

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
        node_info = [[y['node'], y['status'], y['url']] for y in all_nodes['items'] if y['node'] in node_list]
    else:
        node_info = [[x['node'], x['status'], x['url']] for x in all_nodes['items']]

    print pprint_table(data=node_info, headers=["Node","Status","Address"], show_header=True)


if __name__ == '__main__':
    # Initialize framework
    myWazuh = Wazuh(get_init=True)
    # get arguments
    args = parser.parse_args()

    if args.push:
        try:
            check_cluster_config(read_config())
        except WazuhException as e:
            print("Error doing synchronization: {0}".format(str(e)))
            exit(1)

        sync(debug=False)

    elif args.manager is not None and args.files is None and args.force is None:
        logging.error("Invalid argument: -m parameter requires -f or --force")

    elif args.files is not None:
        _get_file_status(args.files, args.manager)

    elif args.agents is not None:
        _get_agents_status()

    elif args.nodes is not None:
        _get_nodes_status(args.nodes)

    elif args.force is not None:
        try:
            check_cluster_config(read_config())
        except WazuhException as e:
            print("Error doing synchronization: {0}".format(str(e)))
            exit(1)

        if args.manager is None:
            sync(debug=False, force=True)
        else:
            for node in args.manager:
                sync_one_node(debug=False, node=node, force=True)

    elif args.scan is not None:
        try:
            scan_for_new_files()
        except socket.error as e:
            print("Error connecting to wazuh cluster service: {0}".format(str(e)))
            exit(1)

    else:
        parser.print_help()
        exit()
