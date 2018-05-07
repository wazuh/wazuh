#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from os.path import dirname, basename
from sys import argv, exit, path
from itertools import chain
import argparse
import logging
import json
from signal import signal, SIGINT
import collections

# Import framework
try:
    # Search path
    path.append(dirname(argv[0]) + '/../framework')

    # Import Wazuh and Initialize
    from wazuh import Wazuh
    from wazuh.exception import WazuhException

    myWazuh = Wazuh(get_init=True)

    # Import cluster
    from wazuh.cluster.cluster import read_config, check_cluster_config, get_status_json
    from wazuh.cluster.communication import send_to_internal_socket

except Exception as e:
    print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
    exit()

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def get_parser(type):
    if type == "master":
        class WazuhHelpFormatter(argparse.ArgumentParser):
            def format_help(self):
                msg = """Wazuh cluster control - Master node

Syntax: {0} --help | --health [more] [--debug] | --list-agents [-fs Status] [-fn Node1 NodeN] [--debug] | --list-nodes [-fn Node1 NodeN] [--debug]

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
                #\t-s, --sync                                 # Force the nodes to initiate the synchronization process
                #\t-l, --list-files                           # List the file status for every node
                #\t-f, --filter-file                          # Filter by file
                return msg
            def error(self, message):
                print("Wrong arguments: {0}".format(message))
                self.print_help()
                exit(1)

        parser=WazuhHelpFormatter(usage='custom usage')
        parser._positionals.title = 'Wazuh Cluster control interface'

        parser.add_argument('-fn', '--filter-node', dest='filter_node', nargs='*', type=str, help="Node")
        #parser.add_argument('-f', '--filter-file', dest='filter_file', nargs='*', type=str, help="File")
        parser.add_argument('-fs', '--filter-agent-status', dest='filter_status', nargs='*', type=str, help="Agents status")
        parser.add_argument('-d', '--debug', action='store_const', const='debug', help="Enable debug mode")

        exclusive = parser.add_mutually_exclusive_group()
        #exclusive.add_argument('-s', '--sync', const='sync', action='store_const', help="Force the nodes to initiate the synchronization process")
        #exclusive.add_argument('-l', '--list-files', const='list_files', action='store_const', help="List the file status for every node")
        exclusive.add_argument('-a', '--list-agents', const='list_agents', action='store_const', help="List agents")
        exclusive.add_argument('-l', '--list-nodes', const='list_nodes', action='store_const', help="List nodes")
        exclusive.add_argument('-i', '--health', const='health', action='store', nargs='?', help="Show cluster health")

        return parser
    else:
        class WazuhHelpFormatter(argparse.ArgumentParser):
            def format_help(self):
                msg = """Wazuh cluster control - Client node

Syntax: {0} --help | --health [more] [--debug] | --list-nodes [-fn Node1 NodeN] [--debug]

Usage:
\t-h, --help                                  # Show this help message
\t-i, --health [more]                         # Show cluster health
\t-l, --list-nodes                            # List nodes

Filters:
\t-fn, --filter-node                          # Filter by node

Others:
\t-d, --debug                                # Show debug information

""".format(basename(argv[0]))
                #\t-l, --list-files                            # List the status of his own files
                #\t -f, --filter-file                          # Filter by file
                return msg
            def error(self, message):
                print("Wrong arguments: {0}".format(message))
                self.print_help()
                exit(1)

        parser=WazuhHelpFormatter(usage='custom usage')
        parser._positionals.title = 'Wazuh Cluster control interface'

        parser.add_argument('-fn', '--filter-node', dest='filter_node', nargs='*', type=str, help="Node")
        #parser.add_argument('-f', '--filter-file', dest='filter_file', nargs='*', type=str, help="File")
        parser.add_argument('-fs', '--filter-agent-status', dest='filter_status', nargs='*', type=str, help="Agents status")
        parser.add_argument('-d', '--debug', action='store_const', const='debug', help="Enable debug mode")

        exclusive = parser.add_mutually_exclusive_group()
        #exclusive.add_argument('-l', '--list-files', const='list_files', action='store_const', help="List the file status for every node")
        exclusive.add_argument('-a', '--list-agents', const='list_agents', action='store_const', help="List agents")
        exclusive.add_argument('-l', '--list-nodes', const='list_nodes', action='store_const', help="List nodes")
        exclusive.add_argument('-i', '--health', const='health', action='store', nargs='?', help="Show cluster health")
        return parser

def signal_handler(n_signal, frame):
    exit(1)

def __execute(request):
    response_json = {}
    response = None
    try:
        response = send_to_internal_socket(socket_name="c-internal", message=request)
        response_json = json.loads(response)
    except KeyboardInterrupt:
        print ("Interrupted")
        exit(1)
    except Exception as e:
        if response:
            print ("Error: {}".format(response))
        else:
            print ("Error: {}".format(e))
        exit(1)

    return response_json

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

    print (table_str)

#
# Get
#

### Get files
def print_file_status_master(filter_file_list, filter_node_list):
    files = __execute("get_files {}%--%{}".format(filter_file_list, filter_node_list))
    headers = ["Node", "File name", "Modification time", "MD5"]

    node_error = {}

    data = []
    # Convert JSON data to table format
    for node_name in sorted(files.iterkeys()):

        if not files[node_name]:
            continue
        if not isinstance(files[node_name], dict):
            node_error[node_name] = files[node_name]
            continue

        for file_name in sorted(files[node_name].iterkeys()):
            file = [node_name, file_name, files[node_name][file_name]['mod_time'].split('.', 1)[0], files[node_name][file_name]['md5']]
            data.append(file)

    __print_table(data, headers, True)

    if len(node_error) > 0:
        print ("Error:")
        for node, error in node_error.iteritems():
            print (" - {}: {}".format(node, error))


def print_file_status_client(filter_file_list, node_name):
    my_files = __execute("get_files {}".format(filter_file_list))

    if my_files.get("err"):
        print ("Err {}")
        exit(1)

    headers = ["Node", "File name", "Modification time", "MD5"]
    data = []
    for file_name in sorted(my_files.iterkeys()):
            file = [node_name, file_name, my_files[file_name]['mod_time'].split('.', 1)[0], my_files[file_name]['md5']]
            data.append(file)

    __print_table(data, headers, True)
    print ("(*) Clients only show their own files.")


### Get nodes
def print_nodes_status(filter_node):
    nodes = __execute("get_nodes {}".format(filter_node) if filter_node else "get_nodes")

    if nodes.get("err"):
        print ("Err {}")
        exit(1)

    headers = ["Name", "Address", "Type"]
    data = [[nodes[node_name]['name'], nodes[node_name]['ip'], nodes[node_name]['type']] for node_name in sorted(nodes.iterkeys())]
    __print_table(data, headers, True)


### Sync
def sync_master(filter_node):
    node_response = __execute("sync {}".format(filter_node) if filter_node else "sync")
    headers = ["Node", "Response"]
    data = [[node, response] for node, response in node_response.iteritems()]
    __print_table(data, headers, True)


### Get agents
def print_agents_master(filter_status=None, filter_node=None):
    filter_status_f = None
    if filter_status:
        filter_status_f = filter_status[0].lower().replace(" ", "").replace("-", "")
        if filter_status_f == "neverconnected":
            filter_status_f = "Never connected"
        elif filter_status_f == "active":
            filter_status_f = "Active"
        elif filter_status_f == "disconnected":
            filter_status_f = "Disconnected"
        elif filter_status_f == "pending":
            filter_status_f = "Pending"
        else:
            print ("Error: '{}' is not a valid agent status. Try with 'Active', 'Disconnected', 'NeverConnected' or 'Pending'.".format(filter_status[0].lower().replace(" ", "")))
            exit(0)
    agents = __execute("get_agents {}%--%{}".format(filter_status_f, filter_node))
    headers = ["ID", "Address", "Name", "Status", "Node"]
    __print_table(agents, headers, True)
    if filter_status_f:
        print ("Found {} agent(s) with status '{}'.".format(len(agents), filter_status_f))
    else:
        print ("Listing {} agent(s).".format(len(agents)))


### Get healthchech
def print_healthcheck(conf, more=False, filter_node=None):
    node_response = __execute("get_health")

    msg1 = ""
    msg2 = ""

    msg1 += "Cluster name: {}\n\n".format(conf['name'])

    if not more:
        msg1 += "Last completed synchronization for connected nodes ({}):\n".format(node_response["n_connected_nodes"])
    else:
        msg1 += "Connected nodes ({}):".format(node_response["n_connected_nodes"])

    for node, node_info in sorted(node_response["nodes"].items()):

        if filter_node and node not in filter_node:
            continue

        msg2 += "\n    {} ({})\n".format(node, node_info['info']['ip'])
        msg2 += "        Version: {}\n".format(node_info['info']['version'])
        msg2 += "        Type: {}\n".format(node_info['info']['type'])
        msg2 += "        Active agents: {}\n".format(node_info['info']['n_active_agents'])

        if node_info['info']['type'] != "master":

            if not more:
                msg1 += "    {} ({}): Integrity: {} | Agents-info: {} | Agent-groups: {}.\n".format(node, node_info['info']['ip'], node_info['status']['last_sync_integrity']['date_end_master'], node_info['status']['last_sync_agentinfo']['date_end_master'], node_info['status']['last_sync_agentgroups']['date_end_master']
                    )

            msg2 += "        Status:\n"

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

    # Get cluster config
    try:
        cluster_config = read_config()
    except WazuhException as e:
        cluster_config = None

    if not cluster_config or cluster_config['disabled'] == 'yes':
        print ("Error: The cluster is disabled")
        exit(1)

    # Validate cluster config
    try:
        check_cluster_config(cluster_config)
    except WazuhException as e:
        clean_exit(reason="Invalid configuration: '{0}'".format(str(e)), error=True)

    status = get_status_json()
    if status["running"] != "yes":
        print ("Error: The cluster is not running")
        exit(1)

    is_master = cluster_config['node_type'] == "master"

    # get arguments
    parser = get_parser(cluster_config['node_type'])
    args = parser.parse_args()

    if args.debug:
        logging.getLogger('').setLevel(logging.DEBUG) #10

    try:
        if args.list_agents:
            if is_master:
                print_agents_master(args.filter_status, args.filter_node)
            else:
                print ("Wrong arguments. To use this command you need to be a master node.")
                parser.print_help()

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

        #elif args.list_files is not None:
        #    print_file_status_master(args.filter_file, args.filter_node) if is_master else print_file_status_client(args.filter_file, cluster_config['node_name'])
        #elif is_master and args.sync is not None:
        #    sync_master(args.filter_node)
        #elif args.list_files is not None:
        #    print_file_status_master(args.filter_file, args.filter_node) if is_master else print_file_status_client(args.filter_file, cluster_config['node_name'])

    except Exception as e:
        logging.error(str(e))
        if args.debug:
            raise
        exit(1)
