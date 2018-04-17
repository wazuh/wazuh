#!/usr/bin/env python

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
                msg = """
{0} --help | --sync [-t Node1 NodeN] [--debug] | --list-files [-t Node1 NodeN] [-f File1 FileN] [--debug] | --list-agents [--debug] [-c] | --list-nodes [-t Node1 NodeN] [--debug]

Usage:
\t-h, --help                                  # Show this help message
\t-a, --list-agents                           # List agents
\t-n, --list-nodes                            # List nodes

Filters:
\t -t, --filter-node                          # Filter by node
\t -c, --filter-agents-status                 # Filter by agent status

Others:
\t     --debug                                # Show debug information

""".format(basename(argv[0]))
                #\t-s, --sync                                 # Force the nodes to initiate the synchronization process
                #\t-l, --list-files                           # List the file status for every node
                #\t-f, --filter-file                         # Filter by file
                return msg
            def error(self, message):
                print("Wrong arguments: {0}".format(message))
                self.print_help()
                exit(1)

        parser=WazuhHelpFormatter(usage='custom usage')
        parser._positionals.title = 'Wazuh Cluster control interface'

        parser.add_argument('-t', '--filter-node', dest='filter_node', nargs='*', type=str, help="Node")
        #parser.add_argument('-f', '--filter-file', dest='filter_file', nargs='*', type=str, help="File")
        parser.add_argument('-c', '--filter-agents-status', dest='filter_status', nargs='*', type=str, help="Agents status")
        parser.add_argument('--debug', action='store_const', const='debug', help="Enable debug mode")

        exclusive = parser.add_mutually_exclusive_group()
        #exclusive.add_argument('-s', '--sync', const='sync', action='store_const', help="Force the nodes to initiate the synchronization process")
        #exclusive.add_argument('-l', '--list-files', const='list_files', action='store_const', help="List the file status for every node")
        exclusive.add_argument('-a', '--list-agents', const='list_agents', action='store_const', help="List agents")
        exclusive.add_argument('-n', '--list-nodes', const='list_nodes', action='store_const', help="List nodes")
        return parser
    else:
        class WazuhHelpFormatter(argparse.ArgumentParser):
            def format_help(self):
                msg = """
{0} --help | --list-files [-f File1 FileN] [--debug] | --list-nodes [-t Node1 NodeN] [--debug]

Usage:
\t-h, --help                                  # Show this help message
\t-n, --list-nodes                            # List nodes

Filters:
\t -t, --filter-node                          # Filter by node

Others:
\t     --debug                                # Show debug information

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

        parser.add_argument('-t', '--filter-node', dest='filter_node', nargs='*', type=str, help="Node")
        #parser.add_argument('-f', '--filter-file', dest='filter_file', nargs='*', type=str, help="File")
        parser.add_argument('-c', '--filter-agents-status', dest='filter_status', nargs='*', type=str, help="Agents status")
        parser.add_argument('--debug', action='store_const', const='debug', help="Enable debug mode")

        exclusive = parser.add_mutually_exclusive_group()
        #exclusive.add_argument('-l', '--list-files', const='list_files', action='store_const', help="List the file status for every node")
        exclusive.add_argument('-a', '--list-agents', const='list_agents', action='store_const', help="List agents")
        exclusive.add_argument('-n', '--list-nodes', const='list_nodes', action='store_const', help="List nodes")
        return parser


def signal_handler(n_signal, frame):
    exit(1)


def __execute(request):
    response = ""
    try:
        response = send_to_internal_socket(socket_name="c-internal", message=request)
    except KeyboardInterrupt:
        pass
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

    print table_str

#
# Get
#

### Get files
def print_file_status_master(filter_file_list, filter_node_list):
    files = json.loads(__execute("get_files {}%--%{}".format(filter_file_list, filter_node_list)))
    headers = ["Node", "File name", "Modification time", "MD5"]

    data = []
    for node_name in sorted(files.iterkeys()):
        if not files[node_name]:
            continue
        for file_name in sorted(files[node_name].iterkeys()):
            file = [node_name, file_name, files[node_name][file_name]['mod_time'].split('.', 1)[0], files[node_name][file_name]['md5']] 
            data.append(file)

    __print_table(data, headers, True)


def print_file_status_client(filter_file_list, node_name):
    my_files = json.loads(__execute("get_files {}".format(filter_file_list)))
    headers = ["Node", "File name", "Modification time", "MD5"]
    
    data = []
    for file_name in sorted(my_files.iterkeys()):
            file = [node_name, file_name, my_files[file_name]['mod_time'].split('.', 1)[0], my_files[file_name]['md5']] 
            data.append(file)
            
    __print_table(data, headers, True)
    print "(*) Clients only show their own files"


### Get nodes
def print_nodes_status(filter_node):
    nodes = json.loads(__execute("get_nodes {}".format(filter_node) if filter_node else "get_nodes"))
    headers = ["Name", "Address", "Type"]
    data = [[nodes[node_name]['name'], nodes[node_name]['ip'], nodes[node_name]['type']] for node_name in sorted(nodes.iterkeys())]
    __print_table(data, headers, True)


### Sync
def sync_master(filter_node):
    node_response = json.loads(__execute("sync {}".format(filter_node) if filter_node else "sync"))
    headers = ["Node", "Response"]
    data = [[node, response] for node, response in node_response.iteritems()]
    __print_table(data, headers, True)


### Get agents
def print_agents_master(filter_status):
    if filter_status:
        filter_status = filter_status[0].lower().replace(" ", "")
        if filter_status == "neverconnected":
            filter_status = "Never connected"
        elif filter_status == "active":
            filter_status = "Active"
        elif filter_status == "disconnected":
            filter_status = "Disconnected"
        elif filter_status == "pending":
            filter_status = "Pending"
    agents = json.loads(__execute("get_agents {}".format(filter_status)))
    headers = ["ID", "Address", "Name", "Status", "Node"]
    __print_table(agents, headers, True)


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
        raise WazuhException(3000, "The cluster is disabled")
        exit(1)

    # Validate cluster config
    try:
        check_cluster_config(cluster_config)
    except WazuhException as e:
        clean_exit(reason="Invalid configuration: '{0}'".format(str(e)), error=True)

    status = get_status_json()
    if status["running"] != "yes":
        raise WazuhException(3000, "The cluster is not running")
        exit(1)

    is_master = cluster_config['node_type'] == "master"

    # get arguments
    parser = get_parser(cluster_config['node_type'])
    args = parser.parse_args()

    if args.debug:
        logging.getLogger('').setLevel(logging.DEBUG) #10

    try:
        if is_master and args.list_agents is not None:
            print_agents_master(args.filter_status)
            #if args.list_files is not None:
            #    print_file_status_master(args.filter_file, args.filter_node) if is_master else print_file_status_client(args.filter_file, cluster_config['node_name'])
            #elif is_master and args.sync is not None:
            #    sync_master(args.filter_node)
        elif args.list_nodes is not None:
            print_nodes_status(args.filter_node)
        else:
            parser.print_help()
            exit()

    except Exception as e:
        logging.error(str(e))
        if args.debug:
            raise
        exit(1)
