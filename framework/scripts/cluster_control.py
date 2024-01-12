#!/usr/bin/env python

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import asyncio
import itertools
import logging
import operator
import sys
from os import path
from typing import Union

import wazuh.core.cluster.cluster
import wazuh.core.cluster.utils
from wazuh.core.cluster import control, local_client
from wazuh.core.common import DECIMALS_DATE_FORMAT
from wazuh.core.utils import get_utc_strptime


def __print_table(data: map, headers: dict, show_header: bool = False):
    """Pretty print list of lists.

    Paramaters
    ----------
    data : map
        Data to be printed.
    headers : dict
        Table headers.
    show_header : bool
        Whether to show the table header or not.
    """

    def get_max_size_cols(l: map) -> list:
        """For each column of the table, return the size of the biggest element.

        Parameters
        ----------
        l : map
            Table.

        Returns
        -------
        list
            List containing the biggest element size of each column of the given table.
        """
        return list(map(lambda x: max(map(lambda y: len(y) + 2, x)), map(list, zip(*l))))

    if show_header:
        table = list(itertools.chain([tuple(map(lambda x: x.upper(), headers))], data))
    else:
        table = data

    sizes = get_max_size_cols(table)

    table_str = '\n'.join(
        [''.join(["{}{}".format(col, " " * (max_size - len(col))) for col, max_size in zip(row, sizes)])
         for row in table])
    print(table_str)


async def print_agents(filter_status: list, filter_node: list):
    """Print table with the agents information.

    Parameters
    ----------
    filter_node : list
        Nodes to return.
    filter_status : list
        Agent connection statuses to filter by.
    """
    lc = local_client.LocalClient()
    result = await control.get_agents(lc, filter_node=filter_node, filter_status=filter_status)
    headers = {'id': 'ID', 'name': 'Name', 'ip': 'IP', 'status': 'Status', 'version': 'Version',
               'node_name': 'Node name'}
    data = map(operator.itemgetter(*headers.keys()), result['items'])
    __print_table(data, list(headers.values()), True)


async def print_nodes(filter_node: list):
    """Print table with the cluster nodes.

    Parameters
    ----------
    filter_node : list
        Nodes to return.
    """
    lc = local_client.LocalClient()
    result = await control.get_nodes(lc, filter_node=filter_node)
    headers = ["Name", "Type", "Version", "Address"]
    data = map(lambda x: list(x.values()), result['items'])
    __print_table(data, headers, True)


async def print_health(config: dict, more: bool, filter_node: Union[str, list]):
    """Print the current status of the cluster as well as additional information.

    Parameters
    ----------
    config : dict
        Cluster current configuration.
    more : bool
        Indicate whether additional information is desired or not.
    filter_node : str or list
        Node to return.
    """

    def calculate_seconds(start_time: str, end_time: str):
        """Calculate the time difference between two dates.

        Parameters
        ----------
        start_time : str
            Start date.
        end_time : str
            End date.

        Returns
        -------
        str
            Total seconds between the two dates.
        """
        if end_time != 'n/a' and start_time != 'n/a':
            seconds = \
                get_utc_strptime(end_time, DECIMALS_DATE_FORMAT) - get_utc_strptime(start_time, DECIMALS_DATE_FORMAT)
            total_seconds = f"{round(seconds.total_seconds(), 3) if seconds.total_seconds() >= 0.0005 else 0.001}s"
        else:
            total_seconds = 'n/a'

        return total_seconds

    lc = local_client.LocalClient()
    if filter_node is None:
        filter_node = await control.get_nodes(lc, filter_node=filter_node)
        filter_node = [node['name'] for node in filter_node['items']]
    result = await control.get_health(lc, filter_node=filter_node)
    msg2 = ""

    msg1 = f"Cluster name: {config['name']}\n\n"
    msg1 += f"Last completed synchronization for connected nodes ({result['n_connected_nodes']}):\n" if not more \
        else f"Connected nodes ({result['n_connected_nodes']}):"

    for node, node_info in sorted(result["nodes"].items()):
        msg2 += f"\n    {node} ({node_info['info']['ip']})\n"
        msg2 += f"        Version: {node_info['info']['version']}\n"
        msg2 += f"        Type: {node_info['info']['type']}\n"
        msg2 += f"        Active agents: {node_info['info']['n_active_agents']}\n"

        if node_info['info']['type'] != "master":
            if not more:
                msg1 += f"    {node} ({node_info['info']['ip']}): " \
                        f"Integrity check: {node_info['status']['last_check_integrity']['date_end_master']} | " \
                        f"Integrity sync: {node_info['status']['last_sync_integrity']['date_end_master']} | " \
                        f"Agents-info: {node_info['status']['last_sync_agentinfo']['date_end_master']} | " \
                        f"Agent-groups: {node_info['status']['last_sync_agentgroup']['date_end']} | " \
                        f"Agent-groups full: {node_info['status']['last_sync_full_agentgroup']['date_end']} | " \
                        f"Last keep alive: {node_info['status']['last_keep_alive']}.\n"

            msg2 += "        Status:\n"

            # Last Keep Alive
            msg2 += "            Last keep Alive:\n"
            msg2 += f"                Last received: {node_info['status']['last_keep_alive']}.\n"

            # Integrity check
            total = calculate_seconds(node_info['status']['last_check_integrity']['date_start_master'],
                                      node_info['status']['last_check_integrity']['date_end_master'])
            msg2 += f"            Integrity check:\n"
            msg2 += f"                Last integrity check: {total} " \
                    f"({node_info['status']['last_check_integrity']['date_start_master']} - " \
                    f"{node_info['status']['last_check_integrity']['date_end_master']}).\n"
            msg2 += f"                Permission to check integrity: {node_info['status']['sync_integrity_free']}.\n"

            # Integrity sync
            total = calculate_seconds(node_info['status']['last_sync_integrity']['date_start_master'],
                                      node_info['status']['last_sync_integrity']['date_end_master'])
            msg2 += "            Integrity sync:\n"
            msg2 += f"                Last integrity synchronization: {total} " \
                    f"({node_info['status']['last_sync_integrity']['date_start_master']} - " \
                    f"{node_info['status']['last_sync_integrity']['date_end_master']}).\n"

            n_shared = str(node_info['status']['last_sync_integrity']['total_files']["shared"])
            n_missing = str(node_info['status']['last_sync_integrity']['total_files']["missing"])
            n_extra = str(node_info['status']['last_sync_integrity']['total_files']["extra"])
            msg2 += f"                Synchronized files: Shared: {n_shared} | Missing: {n_missing} | " \
                    f"Extra: {n_extra}.\n"

            # Agent info
            total = calculate_seconds(node_info['status']['last_sync_agentinfo']['date_start_master'],
                                      node_info['status']['last_sync_agentinfo']['date_end_master'])
            msg2 += "            Agents-info:\n"
            msg2 += f"                Last synchronization: {total} " \
                    f"({node_info['status']['last_sync_agentinfo']['date_start_master']} - " \
                    f"{node_info['status']['last_sync_agentinfo']['date_end_master']}).\n"
            msg2 += f"                Number of synchronized chunks: " \
                    f"{node_info['status']['last_sync_agentinfo']['n_synced_chunks']}.\n"
            msg2 += f"                Permission to synchronize agent-info: " \
                    f"{node_info['status']['sync_agent_info_free']}.\n"

            # Agent groups
            total = calculate_seconds(node_info['status']['last_sync_agentgroup']['date_start'],
                                      node_info['status']['last_sync_agentgroup']['date_end'])
            msg2 += "            Agents-groups:\n"
            msg2 += f"                Last synchronization: {total} " \
                    f"({node_info['status']['last_sync_agentgroup']['date_start']} - " \
                    f"{node_info['status']['last_sync_agentgroup']['date_end']}).\n"
            msg2 += f"                Number of synchronized chunks: " \
                    f"{node_info['status']['last_sync_agentgroup']['n_synced_chunks']}.\n"

            # Agent groups full
            total = calculate_seconds(node_info['status']['last_sync_full_agentgroup']['date_start'],
                                      node_info['status']['last_sync_full_agentgroup']['date_end'])
            msg2 += "            Agents-groups full:\n"
            msg2 += f"                Last synchronization: {total} " \
                    f"({node_info['status']['last_sync_full_agentgroup']['date_start']} - " \
                    f"{node_info['status']['last_sync_full_agentgroup']['date_end']}).\n"
            msg2 += f"                Number of synchronized chunks: " \
                    f"{node_info['status']['last_sync_full_agentgroup']['n_synced_chunks']}.\n"
    print(msg1)
    more and print(msg2)


def usage():
    """Show the usage of the parameters."""
    msg = """
    {0} [-h] [-d] [-fn [FILTER_NODE ...]] [-fs [FILTER_STATUS ...]][-a | -l | -i [HEALTH]]
    Usage:
    \t-l                                    # List all nodes present in a cluster
    \t-l -fn <node_name>                    # List certain nodes that belong to the cluster
    \t-a                                    # List all agents connected to the cluster
    \t-a -fn <node_name>                    # Check which agents are reporting to certain nodes
    \t-a -fs <agent_status>                 # List agents with certain status
    \t-a -fn <node_name> <agent_status>     # List agents reporting to certain node and with certain status
    \t-i                                    # Check cluster health
    \t-i -fn <node_name>                    # Check certain node's health


    Params:
    \t-l, --list
    \t-d, --debug
    \t-h, --help
    \t-fn, --filter-node
    \t-fs, --filter-agent-status
    \t-a, --list-agents
    \t-i, --health

    """.format(path.basename(sys.argv[0]))
    print(msg)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true', dest='debug', help="Enable debug mode")
    parser.add_argument('-fn', '--filter-node', dest='filter_node', nargs='*', type=str, help="Filter by node name")
    parser.add_argument('-fs', '--filter-agent-status', dest='filter_status', nargs='*', type=str,
                        help="Filter by agent status")
    exclusive = parser.add_mutually_exclusive_group()
    exclusive.add_argument('-a', '--list-agents', action='store_const', const='list_agents', help='List agents')
    exclusive.add_argument('-l', '--list-nodes', action='store_const', const='list_nodes', help='List nodes')
    exclusive.add_argument('-i', '--health', action='store', nargs='?', const='health', help='Show cluster health')
    exclusive.add_argument('-u', '--usage', action='store_true', help='Show usage')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.ERROR, format='%(levelname)s: %(message)s')

    cluster_status = wazuh.core.cluster.utils.get_cluster_status()
    if cluster_status['enabled'] == 'no' or cluster_status['running'] == 'no':
        logging.error("Cluster is not running.")
        sys.exit(1)

    cluster_config = wazuh.core.cluster.utils.read_config()
    wazuh.core.cluster.cluster.check_cluster_config(config=cluster_config)
    try:
        if args.filter_status and not args.list_agents:
            logging.error("Wrong arguments.")
            usage()
            sys.exit(1)
        elif args.list_agents:
            my_function, my_args = print_agents, (args.filter_status, args.filter_node,)
        elif args.list_nodes:
            my_function, my_args = print_nodes, (args.filter_node,)
        elif args.health:
            more = args.health.lower() == 'more'
            my_function, my_args = print_health, (cluster_config, more, args.filter_node,)
        elif args.usage:
            usage()
            sys.exit(0)
        else:
            parser.print_help()
            sys.exit(0)

        asyncio.run(my_function(*my_args))
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.error(e)
        if args.debug:
            raise


if __name__ == '__main__':
    main()
