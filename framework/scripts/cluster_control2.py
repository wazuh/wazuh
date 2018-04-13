#!/usr/bin/env python

from os.path import dirname, basename
from sys import argv, exit, path
import argparse
import logging
import json
from signal import signal, SIGINT

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
{0} --help | --sync [-t Node1 NodeN] [--debug] | --list-files [-t Node1 NodeN] [-f File1 FileN] [--debug] | --list-agents [--debug] | --list-nodes [-t Node1 NodeN] [-c] [--debug]

Usage:
\t-h, --help                                  # Show this help message
\t-s, --sync                                  # Force the nodes to initiate the synchronization process
\t-l, --list-files                            # List the file status for every node
\t-a, --list-agents                           # List agents
\t-n, --list-nodes                            # List nodes

Filters:
\t -t, --filter-node                          # Filter by node
\t -f, --filter-file                          # Filter by file
\t -c, --filter-connected-agents              # Filter by connected agents

Others:
\t     --debug                                # Show debug information

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
        parser.add_argument('-c', '--filter-connected-agents', dest='filter_connected', nargs='*', type=bool, help="Connected agents")
        parser.add_argument('--debug', action='store_const', const='debug', help="Enable debug mode")

        exclusive = parser.add_mutually_exclusive_group()
        exclusive.add_argument('-s', '--sync', const='sync', action='store_const', help="Force the nodes to initiate the synchronization process")
        exclusive.add_argument('-l', '--list-files', const='list_files', action='store_const', help="List the file status for every node")
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
\t-l, --list-files                            # List the status of his own files
\t-n, --list-nodes                            # List master nodes

Filters:
\t -t, --filter-node                          # Filter by node
\t -f, --filter-file                          # Filter by file

Others:
\t     --debug                                # Show debug information

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
        exclusive.add_argument('-l', '--list-files', const='list_files', action='store_const', help="List the file status for every node")
        exclusive.add_argument('-n', '--list-nodes', const='list_nodes', action='store_const', help="List masters nodes")
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

def __print_head(head, tab_size):
    print "-" * tab_size * (len(head))
    formatted_head = "{}".expandtabs(tab_size).format(head[0])
    i = 0
    while i+1 < len(head):
        i += 1
        formatted_head += "\t{}".expandtabs(tab_size - len(head[i-1])).format(head[i])
    print formatted_head
    print "-" * tab_size * (len(head))


def __print_line_table(array_data, tab_size):
    formatted_head = "{}".expandtabs(tab_size).format(array_data[0])
    i = 0
    while i+1 < len(array_data):
        i += 1
        formatted_head += "\t{}".expandtabs(tab_size - len(array_data[i-1])).format(array_data[i])
    print formatted_head


def __print_table_nodes(nodes, tab_size):
    for node, info_node in nodes.iteritems():
        __print_line_table([info_node['name'], info_node['ip'], info_node['type']], tab_size)


def __print_node_files(head, tab_size, node_name, files):
    for file_name, file_info in files.iteritems():
        __print_line_table([node_name, file_name, file_info['mod_time'], file_info['md5']], tab_size)



#
# Get
#

### Get files
def print_file_status_master(filter_file_list, filter_node_list):
    files = json.loads(__execute("get_files {} {}".format(filter_file_list, filter_node_list)))
    head = ["Node", "Name", "Mod_time", "md5"]
    tab_size = 51
    __print_head(head, tab_size)

    wrong_nodes = []

    for node_name, files in files.iteritems():
        if not files:
            wrong_nodes.append(node_name)
            continue
        __print_node_files(head, tab_size, node_name, files)

    if filter_node_list and wrong_nodes:
        print "Cannot get files of {}".format(", ".join(wrong_nodes))


def print_file_status_client(filter_file_list, node_name):
    my_files = json.loads(__execute("get_files {}".format(filter_file_list)))
    head = ["Node", "Name", "Mod_time", "md5"]
    tab_size = 20
    __print_head(head, tab_size)
    __print_node_files(head, tab_size, node_name, my_files)
    print "(*) Clients can only get his own files"


### Get nodes
def print_nodes_status_master(filter_node, cluster_config):
    nodes = json.loads(__execute("get_nodes {}".format(filter_node) if filter_node else "get_nodes"))

    if not filter_node or cluster_config['node_name'] in filter_node:
        nodes.update({cluster_config['node_name']:{"name": cluster_config['node_name'], "ip": cluster_config['nodes'][0],  "type": "master"}})

    head = ["Name", "Address", "Type"]
    tab_size = 18
    __print_head(head, tab_size)
    __print_table_nodes(nodes, tab_size)


def print_nodes_status_client(filter_node, cluster_config):
    master_node = {"ip": cluster_config['nodes'][0],  "type": "master"}
    head = ["Address", "Type"]
    tab_size = 18
    __print_head(head, tab_size)
    __print_line_table([master_node['ip'], master_node['type']], tab_size)
    print "(*) Clients can only get the master node"


### Sync
def sync_master(filter_node):
    node_response = json.loads(__execute("sync {}".format(filter_node) if filter_node else "sync"))
    head = ["Node", "Response"]
    tab_size = 12
    __print_head(head, tab_size)
    for node, response in node_response.iteritems():
        __print_line_table([node, response], tab_size)


### Get agents
def print_agents_master(filter_connected):
    agents = json.loads(__execute("get_agents {}".format(filter_connected is not None)))
    head = ["ID", "Address", "Name", "Status", "Node"]
    tab_size = 18
    __print_head(head, tab_size)
    for agent in agents:
        __print_line_table(agent, tab_size)


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
        if is_master and args.sync is not None:
            sync_master(args.filter_node)
        elif args.list_files is not None:
            print_file_status_master(args.filter_file, args.filter_node) if is_master else print_file_status_client(args.filter_file, cluster_config['node_name'])
        elif is_master and args.list_agents is not None:
            print_agents_master(args.filter_connected)
        elif args.list_nodes is not None:
            print_nodes_status_master(args.filter_node, cluster_config) if is_master else print_nodes_status_client(args.filter_node, cluster_config)
        else:
            parser.print_help()
            exit()

    except Exception as e:
        logging.error(str(e))
        if args.debug:
            raise
        exit(1)
