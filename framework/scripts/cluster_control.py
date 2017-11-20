#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from sys import path, argv, exit
from os.path import dirname, basename
import argparse
from itertools import chain
parser = argparse.ArgumentParser(description="Wazuh Cluster control interface")
parser.add_argument('-p', '--push', const='push', action='store_const', help="Send all not syncrhonized files")
parser.add_argument('-f', '--files', dest='files', nargs='*', type=str, help="List the status of specified files (all if not specified)")
parser.add_argument('-m', '--manager', dest='manager', nargs='*', type=str, help="List the status of the files of that manager")
parser.add_argument('-a', '--agents', dest='agents', nargs='*', type=bool, help="List all agents")

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
        return map(lambda x: max(map(len, x)), map(list, zip(*l)))

    if show_header:
        table = list(chain.from_iterable([[headers], data]))
    else:
        table = data

    sizes = get_max_size_cols(table)
    
    header_str = "{0}\n".format("-"*(sum(sizes) + 1 + len(sizes)))
    table_str = header_str
    for row in table:
        for col, max_size in zip(row, sizes):
            table_str += "{0}{1} ".format(col, " "*(max_size+1-len(col)))
        table_str += "\n"
        if show_header and row[0] == headers[0]:
            table_str += header_str
    table_str += header_str

    return table_str


def _get_file_status(file_list, manager):
    all_files = get_file_status_all_managers(file_list, manager)
    print pprint_table(data=all_files, headers=["Manager","Filename","Status"], show_header=True)

if __name__ == '__main__':
    # Initialize framework
    myWazuh = Wazuh(get_init=True)
    # get arguments
    args = parser.parse_args()

    if args.push:
        sync(debug=False)

    elif args.files is not None:
        _get_file_status(args.files, args.manager)
