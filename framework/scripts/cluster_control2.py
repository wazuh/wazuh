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
    from wazuh.cluster.cluster import read_config, check_cluster_config
    from wazuh.cluster.communication import send_to_internal_socket

except Exception as e:
    print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
    exit()

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


def signal_handler(n_signal, frame):
    exit(1)


def __execute(request):
    response = ""
    try:
        response = send_to_internal_socket(socket_name="c-internal", message=request)
    except KeyboardInterrupt:
        pass
    return response



def get_file_status_master(file_list, node_list):
    file_status = __execute("req_file_s_c {} {}".format(file_list, node_list))
    print file_status

def get_file_status_client(file_list):
    file_status = __execute("req_file_s_c {}".format(file_list))
    print file_status

def get_nodes_status_master(filter_node):
    nodes = __execute("get_nodes {}".format(filter_node[0]) if filter_node else "get_nodes")
    print nodes

def get_nodes_status_client(master_host):
    node = "Master host {}".format(master_host)
    print node

def sync_master(filter_node):
    node = __execute("req_sync_m_c {}".format(filter_node[0]) if filter_node else "req_sync_m_c all")
    print node

def sync_client():
    node = __execute("req_sync_m_c")
    print node

def get_agents_master():
    agents = __execute("get_agents")
    print agents

def get_agents_client():
    agents = "Only the master can get agents"
    print agents


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

    is_master = cluster_config['node_type'] == "master"

    # get arguments
    args = parser.parse_args()

    if args.debug:
        logging.getLogger('').setLevel(logging.DEBUG) #10

    try:
        #status = get_status_json()
        status = {} # TODO remove this line
        status['running'] = 'yes' # TODO remove this line

        if status['running'] == 'no':
            raise WazuhException(3000, "The cluster is not running")

        try:
            if args.sync is not None:
                sync_master(args.filter_node) if is_master else sync_client()
            elif args.list_files is not None:
                get_file_status_master(args.filter_file, args.filter_node) if is_master else get_file_status_client(args.filter_file)
            elif args.list_agents is not None:
                get_agents_master() if is_master else get_agents_client()
            elif args.list_nodes is not None:
                get_nodes_status_master(args.filter_node) if is_master else get_nodes_status_client(cluster_config['nodes'][0])
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
