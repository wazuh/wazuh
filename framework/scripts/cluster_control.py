#!/usr/bin/env python

# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import itertools
import logging
import argparse
import operator
import sys

import wazuh.core.cluster.cluster
import wazuh.core.cluster.utils
from wazuh.core.cluster import control, local_client


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
        table = list(itertools.chain([tuple(map(lambda x: x.upper(), headers))], data))
    else:
        table = data

    sizes = get_max_size_cols(table)

    table_str = '\n'.join([''.join(["{}{}".format(col, " "*(max_size - len(col))) for col, max_size in zip(row, sizes)])
                           for row in table])
    print(table_str)


async def print_agents(filter_status, filter_node):
    lc = local_client.LocalClient()
    result = await control.get_agents(lc, filter_node=filter_node, filter_status=filter_status)
    headers = {'id': 'ID', 'name': 'Name', 'ip': 'IP', 'status': 'Status', 'version': 'Version',
               'node_name': 'Node name'}
    data = map(operator.itemgetter(*headers.keys()), result['items'])
    __print_table(data, list(headers.values()), True)


async def print_nodes(filter_node):
    lc = local_client.LocalClient()
    result = await control.get_nodes(lc, filter_node=filter_node)
    headers = ["Name", "Type", "Version", "Address"]
    data = map(lambda x: list(x.values()), result['items'])
    __print_table(data, headers, True)


async def print_health(config, more, filter_node):
    lc = local_client.LocalClient()
    result = await control.get_health(lc, filter_node=filter_node)
    msg1 = ""
    msg2 = ""

    msg1 += "Cluster name: {}\n\n".format(config['name'])

    if not more:
        msg1 += "Last completed synchronization for connected nodes ({}):\n".format(result["n_connected_nodes"])
    else:
        msg1 += "Connected nodes ({}):".format(result["n_connected_nodes"])

    for node, node_info in sorted(result["nodes"].items()):

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
            msg2 += "                Last synchronization: {0} - {1}.\n".format(
                node_info['status']['last_sync_integrity']['date_start_master'],
                node_info['status']['last_sync_integrity']['date_end_master'])

            n_shared = str(node_info['status']['last_sync_integrity']['total_files']["shared"])
            n_missing = str(node_info['status']['last_sync_integrity']['total_files']["missing"])
            n_extra = str(node_info['status']['last_sync_integrity']['total_files']["extra"])
            n_extra_valid = str(node_info['status']['last_sync_integrity']['total_files']["extra_valid"])

            msg2 += "                Synchronized files: Shared: {} | Missing: {} | Extra: {} | Extra valid: {}.\n".format(
                n_shared, n_missing, n_extra, n_extra_valid)
            msg2 += "                Permission to synchronize: {}.\n".format(
                str(node_info['status']['sync_integrity_free']))

            # Agent info
            msg2 += "            Agents-info\n"
            msg2 += "                Last synchronization: {0} - {1}.\n".format(
                node_info['status']['last_sync_agentinfo']['date_start_master'],
                node_info['status']['last_sync_agentinfo']['date_end_master'])
            msg2 += "                Number of synchronized chunks: {}.\n".format(
                str(node_info['status']['last_sync_agentinfo']['total_agentinfo']))

            # Agent groups
            msg2 += "            Agents-group\n"
            msg2 += "                Last synchronization: {0} - {1}.\n".format(
                node_info['status']['last_sync_agentgroups']['date_start_master'],
                node_info['status']['last_sync_agentgroups']['date_end_master'])
            msg2 += "                Synchronized files: {}.\n".format(
                str(node_info['status']['last_sync_agentgroups']['total_agentgroups']))
            msg2 += "                Permission to synchronize: {}.\n".format(
                str(node_info['status']['sync_extravalid_free']))

    print(msg1)

    if more:
        print(msg2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true', dest='debug', help="Enable debug mode")
    parser.add_argument('-fn', '--filter-node', dest='filter_node', nargs='*', type=str, help="Filter by node name")
    parser.add_argument('-fs', '--filter-agent-status', dest='filter_status', nargs='*', type=str,
                        help="Filter by agent status")
    exclusive = parser.add_mutually_exclusive_group()
    exclusive.add_argument('-a', '--list-agents', action='store_const', const='list_agents', help='List agents')
    exclusive.add_argument('-l', '--list-nodes', action='store_const', const='list_nodes', help='List nodes')
    exclusive.add_argument('-i', '--health', action='store', nargs='?', const='health', help='Show cluster health')
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
            parser.print_help()
            sys.exit(1)
        elif args.list_agents:
            my_function, my_args = print_agents, (args.filter_status, args.filter_node,)
        elif args.list_nodes:
            my_function, my_args = print_nodes, (args.filter_node,)
        elif args.health:
            more = args.health.lower() == 'more'
            my_function, my_args = print_health, (cluster_config, more, args.filter_node,)
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
