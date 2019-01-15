#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from sys import argv, exit, path, version_info

if version_info[0] == 2 and version_info[1] < 7:
    print("Error: Minimal Python version required is 2.7. Found version is {0}.{1}.".format(version_info[0], version_info[1]))
    exit(1)

from os.path import dirname, basename
from itertools import chain
import argparse
import logging
import signal

def signal_handler(signal, frame):
    print ("Interrupted")
    exit(1)
signal.signal(signal.SIGINT, signal_handler)

# Import framework
try:
    # Search path
    path.append(dirname(argv[0]) + '/../framework')

    # Import Wazuh and Initialize
    from wazuh import Wazuh
    from wazuh.exception import WazuhException

    myWazuh = Wazuh(get_init=True)

    # Import cluster
    from wazuh.cluster.cluster import read_config
    from wazuh.cluster.control import get_nodes, get_healthcheck, get_agents

except Exception as e:
    print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
    exit()

logging.basicConfig(level=logging.ERROR, format='%(levelname)s: %(message)s')


def get_parser():

    class WazuhHelpFormatter(argparse.ArgumentParser):
        def format_help(self):
            msg = """Wazuh cluster control

Syntax: {0} --help | --health [more] [-fn Node1 NodeN] [--debug] | --list-agents [-fs Status] [-fn Node1 NodeN] [--debug] | --list-nodes [-fn Node1 NodeN] [--debug]

Usage:
\t-h, --help                                  # Show this help message
\t-i, --health [more]                         # Show cluster health
\t-a, --list-agents                           # List agents
\t-l, --list-nodes                            # List nodes

Filters:
\t-fn, --filter-node                          # Filter by node
\t-fs, --filter-agent-status                  # Filter by agent status (Active, Disconnected, NeverConnected, Pending)

Others:
\t-d, --debug                                # Show debug information

""".format(basename(argv[0]))
            return msg
        def error(self, message):
            print("Wrong arguments: {0}".format(message))
            self.print_help()
            exit(1)

    parser = WazuhHelpFormatter(usage='custom usage')
    parser._positionals.title = 'Wazuh Cluster control interface'

    parser.add_argument('-fn', '--filter-node', dest='filter_node', nargs='*', type=str, help="Node")
    parser.add_argument('-fs', '--filter-agent-status', dest='filter_status', nargs='*', type=str, help="Agents status")
    parser.add_argument('-d', '--debug', action='store_const', const='debug', help="Enable debug mode")

    exclusive = parser.add_mutually_exclusive_group()
    exclusive.add_argument('-a', '--list-agents', const='list_agents', action='store_const', help="List agents")
    exclusive.add_argument('-l', '--list-nodes', const='list_nodes', action='store_const', help="List nodes")
    exclusive.add_argument('-i', '--health', const='health', action='store', nargs='?', help="Show cluster health")

    return parser


def __execute(my_function, my_args=()):
    response = {}
    try:
        response = my_function(*my_args)
        if response.get("err"):
            print("Error: {}".format(response['err']))
            exit(1)
    except Exception as e:
        print("ERROR: {}".format(e))
        exit(1)

    return response

#
# Format
#

def __print_table(data, headers, show_header=False):
    """
    Pretty print list of lists
    """
    def get_max_size_cols(l):
        """
        For each column of the table, return the size of the biggest element
        """
        return list(map(lambda x: max(map(lambda y: len(y)+2, x)), map(list, zip(*l))))

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

    print (table_str)


### Get nodes
def print_nodes_status(filter_node=None):
    response = __execute(my_function=get_nodes, my_args=(filter_node,))

    nodes = response["items"]
    headers = ["Name", "Address", "Type", "Version"]
    data = [[nodes[node_name]['name'], nodes[node_name]['ip'], nodes[node_name]['type'], nodes[node_name]['version']] for node_name in sorted(nodes.keys())]
    __print_table(data, headers, True)

    if len(response["node_error"]):
        print ("The following nodes could not be found: {}.".format(' ,'.join(response["node_error"])))

### Get agents
def print_agents(filter_status, filter_node, is_master):
    agents = get_agents(filter_status, filter_node, is_master)
    try:
        table = ["  ID: {}, Name: {}, IP: {}, Status: {},  Node: {}".format(agent['id'], agent['name'], agent['ip'],
                                                                            agent['status'], agent['node_name'])
                 for agent in agents['items']]
        print('\n'.join(table))

    except Exception as e:
        print ("{}".format(e))
        exit(1)

    if filter_status:
        print ("\nFound {} agent(s) with status '{}'.".format(agents['totalItems'], ' '.join(filter_status)))
    else:
        print ("\nListing {} agent(s).".format(agents['totalItems']))


### Get healthchech
def print_healthcheck(conf, more=False, filter_node=None):
    node_response = __execute(my_function=get_healthcheck, my_args=(filter_node,))

    msg1 = ""
    msg2 = ""

    msg1 += "Cluster name: {}\n\n".format(conf['name'])

    if not more:
        msg1 += "Last completed synchronization for connected nodes ({}):\n".format(node_response["n_connected_nodes"])
    else:
        msg1 += "Connected nodes ({}):".format(node_response["n_connected_nodes"])

    for node, node_info in sorted(node_response["nodes"].items()):

        msg2 += "\n    {} ({})\n".format(node, node_info['info']['ip'])
        msg2 += "        Version: {}\n".format(node_info['info']['version'])
        msg2 += "        Type: {}\n".format(node_info['info']['type'])
        msg2 += "        Active agents: {}\n".format(node_info['info']['n_active_agents'])

        if node_info['info']['type'] != "master":

            if not more:
                msg1 += "    {} ({}): Integrity: {} | Agents-info: {} | Agent-groups: {} | Last keep alive: {}.\n".format(
                            node, node_info['info']['ip'], node_info['status']['last_sync_integrity']['date_end_master'],
                            node_info['status']['last_sync_agentinfo']['date_end_master'],
                            node_info['status']['last_sync_agentgroups']['date_end_master'],
                            node_info['status']['last_keep_alive']
                    )

            msg2 += "        Status:\n"

            # Last Keep Alive
            msg2 += "            Last keep Alive:\n"
            msg2 += "                Last received: {0}.\n".format(node_info['status']['last_keep_alive'])

            # Integrity
            msg2 += "            Integrity\n"
            msg2 += "                Last synchronization: {0} - {1}.\n".format(node_info['status']['last_sync_integrity']['date_start_master'], node_info['status']['last_sync_integrity']['date_end_master'])

            n_shared = str(node_info['status']['last_sync_integrity']['total_files']["shared"])
            n_missing = str(node_info['status']['last_sync_integrity']['total_files']["missing"])
            n_extra = str(node_info['status']['last_sync_integrity']['total_files']["extra"])
            n_extra_valid = str(node_info['status']['last_sync_integrity']['total_files']["extra_valid"])

            msg2 += "                Synchronized files: Shared: {} | Missing: {} | Extra: {} | Extra valid: {}.\n".format(n_shared, n_missing, n_extra, n_extra_valid)
            msg2 += "                Permission to synchronize: {}.\n".format(str(node_info['status']['sync_integrity_free']))

            # Agent info
            msg2 += "            Agents-info\n"
            msg2 += "                Last synchronization: {0} - {1}.\n".format(node_info['status']['last_sync_agentinfo']['date_start_master'], node_info['status']['last_sync_agentinfo']['date_end_master'])
            msg2 += "                Synchronized files: {}.\n".format(str(node_info['status']['last_sync_agentinfo']['total_agentinfo']))
            msg2 += "                Permission to synchronize: {}.\n".format(str(node_info['status']['sync_agentinfo_free']))

            # Agent groups
            msg2 += "            Agents-group\n"
            msg2 += "                Last synchronization: {0} - {1}.\n".format(node_info['status']['last_sync_agentgroups']['date_start_master'], node_info['status']['last_sync_agentgroups']['date_end_master'])
            msg2 += "                Synchronized files: {}.\n".format(str(node_info['status']['last_sync_agentgroups']['total_agentgroups']))
            msg2 += "                Permission to synchronize: {}.\n".format(str(node_info['status']['sync_extravalid_free']))


    print(msg1)

    if more:
        print(msg2)

#
# Main
#
if __name__ == '__main__':

    # Validate cluster config
    cluster_config = None
    try:
        cluster_config = read_config()
        if 'node_type' not in cluster_config or (cluster_config['node_type'] != 'master' and cluster_config['node_type'] != 'worker'):
            raise WazuhException(3004, 'Invalid node type {0}. Correct values are master and worker'.format(cluster_config['node_type']))
    except WazuhException as e:
        print( "Invalid configuration: '{0}'".format(str(e)))
        exit(1)

    # Get cluster config
    is_master = cluster_config['node_type'] == "master"
    # get arguments
    parser = get_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger('').setLevel(logging.DEBUG) #10

    try:
        if args.filter_status and not args.list_agents:
            print ("Wrong arguments.")
            parser.print_help()
        elif args.list_agents:
            print_agents(args.filter_status, args.filter_node, is_master)

        elif args.list_nodes:
            print_nodes_status(args.filter_node)
        elif args.health:
            more = False
            if args.health.lower() == 'more':
                more = True
            print_healthcheck(conf=cluster_config, more=more, filter_node=args.filter_node)
        else:
            parser.print_help()
            exit()

    except Exception as e:
        logging.error(str(e))
        if args.debug:
            raise
        exit(1)
