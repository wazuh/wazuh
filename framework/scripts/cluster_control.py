#!/var/ossec/python/bin/python3

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import itertools
import json
import logging
import argparse
import sys
from wazuh.cluster import local_client, cluster


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
        table = list(itertools.chain([headers], data))
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


async def print_agents(filter_status, filter_node):
    pass


async def print_nodes(filter_node, client):
    result = json.loads(await client.send_request_and_close(command=b'get_nodes', data=b''))
    headers = [x.capitalize() for x in next(iter(result.values())).keys()]
    data = map(lambda x: list(x.values()), result.values())
    __print_table(data, headers, True)


async def print_health(config, more, filter_node):
    pass


async def async_main(my_function, func_args, configuration, enable_ssl):
    my_client = local_client.LocalClient(configuration=configuration, enable_ssl=enable_ssl, performance_test=0,
                                         concurrency_test=0, file='', string=0, logger=logging.getLogger(),
                                         tag="Cluster control")
    try:
        await asyncio.gather(my_client.start(), my_function(*func_args, my_client))
    except asyncio.CancelledError:
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--ssl', help="Enable communication over SSL", action='store_true', dest='ssl')
    parser.add_argument('-d', '--debug', action='store_true', dest='debug', help="Enable debug mode")
    parser.add_argument('-fn', '--filter-node', dest='filter_node', nargs='*', type=str, help="Filter by node name")
    parser.add_argument('-fs', '--filter-agent-status', dest='filter_status', nargs='*', type=str,
                        help="Filter by agent status")
    exclusive = parser.add_mutually_exclusive_group()
    exclusive.add_argument('-a', '--list-agents', action='store_const', const='list_agents', help='List agents')
    exclusive.add_argument('-l', '--list-nodes', action='store_const', const='list_nodes', help='List nodes')
    exclusive.add_argument('-i', '--health', action='store', nargs='?', const='health', help='Show cluster health')
    args = parser.parse_args()

    cluster_config = cluster.read_config()
    #cluster.check_cluster_config(config=cluster_config)

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.ERROR, format='%(levelname)s: %(message)s')

    try:
        if args.filter_status and not args.list_agents:
            logging.error("Wrong arguments.")
            parser.print_help()
            sys.exit(1)
        elif args.list_agents:
            my_function, my_args = print_agents, (args.filter_status, args.filter_node)
        elif args.list_nodes:
            my_function, my_args = print_nodes, (args.filter_node,)
        elif args.health:
            more = args.health.lower() == 'more'
            my_function, my_args = print_health, (cluster_config, more, args.filter_node,)
        else:
            parser.print_help()
            sys.exit(0)

        asyncio.run(async_main(my_function, my_args, cluster_config, args.ssl))
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.error(e)
        if args.debug:
            raise
