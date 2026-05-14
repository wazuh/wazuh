# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Union

from wazuh.core import common
from wazuh.core.cluster import local_client
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.control import get_health, get_nodes, get_node_ruleset_integrity
from wazuh.core.cluster.utils import get_cluster_status, read_cluster_config, read_config
from wazuh.core.exception import WazuhError, WazuhResourceNotFound
from wazuh.core.results import AffectedItemsWazuhResult, WazuhResult
from wazuh.rbac.decorators import expose_resources, async_list_handler

cluster_enabled = not read_cluster_config(from_import=True)['disabled']
node_id = get_node().get('node') if cluster_enabled else None
node_type = get_node().get('type') if cluster_enabled else 'master'


@expose_resources(actions=['cluster:read'], resources=[f'node:id:{node_id}'])
def read_config_wrapper() -> AffectedItemsWazuhResult:
    """Wrapper for read_config.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
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
def get_node_wrapper() -> AffectedItemsWazuhResult:
    """Wrapper for get_node.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
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
def get_status_json() -> WazuhResult:
    """Return the cluster status.

    Returns
    -------
    WazuhResult
        WazuhResult object with the cluster status.
    """
    return WazuhResult({'data': get_cluster_status()})


@expose_resources(actions=['cluster:read'], resources=['node:id:{filter_node}'], post_proc_func=async_list_handler)
async def get_health_nodes(lc: local_client.LocalClient,
                           filter_node: Union[str, list] = None) -> AffectedItemsWazuhResult:
    """Wrapper for get_health.

    Parameters
    ----------
    lc : LocalClient object
        LocalClient with which to send the 'get_nodes' request.
    filter_node : str or list
        Node to return.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
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
async def get_nodes_info(lc: local_client.LocalClient, filter_node: Union[str, list] = None,
                         **kwargs: dict) -> AffectedItemsWazuhResult:
    """Wrapper for get_nodes.

    Parameters
    ----------
    lc : LocalClient object
        LocalClient with which to send the 'get_nodes' request.
    filter_node : str or list
        Node to return.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
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


@expose_resources(actions=['cluster:read'], resources=[f"node:id:{node_id}"],
                  post_proc_func=async_list_handler)
async def get_ruleset_sync_status(master_md5: dict = None):
    """Compare node's md5 with the master node's to check the custom ruleset synchronization status.

    Parameters
    ----------
    master_md5 : dict
        Master node's ruleset integrity.

    Returns
    -------
    AffectedItemsWazuhResult
        Result with current node's custom ruleset integrity.
    """
    result = AffectedItemsWazuhResult(all_msg="Nodes ruleset synchronization status was successfully read",
                                      some_msg="Could not read ruleset synchronization status in some nodes",
                                      none_msg="Could not read ruleset synchronization status",
                                      sort_casting=["str"]
                                      )

    try:
        lc = local_client.LocalClient()
        node_ruleset_integrity = await get_node_ruleset_integrity(lc)
    except WazuhError as e:
        result.add_failed_item(id_=node_id, error=e)
    else:
        result.affected_items.append({'name': node_id,
                                      'synced': master_md5 == node_ruleset_integrity})
    result.total_affected_items = len(result.affected_items)

    return result
