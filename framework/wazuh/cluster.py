# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh.core import common
from wazuh.core.cluster import local_client
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.control import get_health, get_nodes
from wazuh.core.cluster.utils import get_cluster_status, read_cluster_config, read_config
from wazuh.core.exception import WazuhError, WazuhResourceNotFound
from wazuh.core.results import AffectedItemsWazuhResult, WazuhResult
from wazuh.rbac.decorators import expose_resources, async_list_handler

cluster_enabled = not read_cluster_config()['disabled']
node_id = get_node().get('node') if cluster_enabled else None


@expose_resources(actions=['cluster:read'], resources=[f'node:id:{node_id}'])
def read_config_wrapper():
    """ Wrapper for read_config

    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(all_msg='All selected information was returned',
                                      none_msg='No information was returned'
                                      )
    try:
        result.affected_items.append(read_config())
    except WazuhError as e:
        result.add_failed_item(id_=node_id, error=e)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=['cluster:read'], resources=[f'node:id:{node_id}'])
def get_node_wrapper():
    """ Wrapper for get_node

    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(all_msg='All selected information was returned',
                                      none_msg='No information was returned'
                                      )
    try:
        result.affected_items.append(get_node())
    except WazuhError as e:
        result.add_failed_item(id_=node_id, error=e)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=['cluster:status'], resources=['*:*:*'], post_proc_func=None)
def get_status_json():
    """
    Returns the cluster status

    :return: Dictionary with the cluster status.
    """
    return WazuhResult({'data': get_cluster_status()})


@expose_resources(actions=['cluster:read'], resources=['node:id:{filter_node}'], post_proc_func=async_list_handler)
async def get_health_nodes(lc: local_client.LocalClient, filter_node=None):
    """ Wrapper for get_health """
    result = AffectedItemsWazuhResult(all_msg='All selected nodes healthcheck information was returned',
                                      some_msg='Some nodes healthcheck information was not returned',
                                      none_msg='No healthcheck information was returned'
                                      )

    data = await get_health(lc, filter_node=filter_node)
    for v in data['nodes'].values():
        result.affected_items.append(v)

    result.affected_items = sorted(result.affected_items, key=lambda i: i['info']['name'])
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=['cluster:read'], resources=['node:id:{filter_node}'], post_proc_func=async_list_handler)
async def get_nodes_info(lc: local_client.LocalClient, filter_node=None, **kwargs):
    """ Wrapper for get_nodes """
    result = AffectedItemsWazuhResult(all_msg='All selected nodes information was returned',
                                      some_msg='Some nodes information was not returned',
                                      none_msg='No information was returned'
                                      )

    nodes = set(filter_node).intersection(set(common.cluster_nodes.get()))
    non_existent_nodes = set(filter_node) - nodes
    data = await get_nodes(lc, filter_node=list(nodes), **kwargs)
    for item in data['items']:
        result.affected_items.append(item)

    for node in non_existent_nodes:
        result.add_failed_item(id_=node, error=WazuhResourceNotFound(1730))
    result.total_affected_items = data['totalItems']

    return result
