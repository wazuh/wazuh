# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Union

from wazuh.core import common
from wazuh.core.cluster import local_client
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.control import get_nodes
from wazuh.core.exception import WazuhError, WazuhResourceNotFound
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.rbac.decorators import async_list_handler, expose_resources

node_id = get_node().get('node')


@expose_resources(actions=['cluster:read'], resources=[f'node:id:{node_id}'])
async def get_node_wrapper() -> AffectedItemsWazuhResult:
    """Get node function wrapper.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    result = AffectedItemsWazuhResult(
        all_msg='All selected information was returned', none_msg='No information was returned'
    )
    try:
        result.affected_items.append(get_node())
    except WazuhError as e:
        result.add_failed_item(id_=node_id, error=e)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=['cluster:read'], resources=['node:id:{filter_node}'], post_proc_func=async_list_handler)
async def get_nodes_info(
    lc: local_client.LocalClient, filter_node: Union[str, list] = None, **kwargs: dict
) -> AffectedItemsWazuhResult:
    """Get nodes function wrapper.

    Parameters
    ----------
    lc : LocalClient object
        LocalClient with which to send the 'get_nodes' request.
    filter_node : str or list
        Node to return.
    kwargs : dict
        Additional keyword arguments to pass to 'get_nodes' request.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    result = AffectedItemsWazuhResult(
        all_msg='All selected nodes information was returned',
        some_msg='Some nodes information was not returned',
        none_msg='No information was returned',
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
