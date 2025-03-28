# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json

from wazuh import WazuhInternalError
from wazuh.core import common
from wazuh.core.cluster import local_client
from wazuh.core.cluster.common import as_wazuh_object
from wazuh.core.utils import filter_array_by_query


async def get_nodes(
    lc: local_client.LocalClient,
    filter_node=None,
    offset=0,
    limit=common.DATABASE_LIMIT,
    sort=None,
    search=None,
    select=None,
    filter_type='all',
    q='',
    distinct: bool = False,
):
    """Get basic information of each of the cluster nodes.

    Parameters
    ----------
    lc : LocalClient object
        LocalClient with which to send the 'get_nodes' request.
    filter_node : str, list
        Node to return.
    offset : int
        First element to return.
    limit : int
        Maximum number of elements to return.
    sort : dict
        Sort the collection by a field or fields.
    search : dict
        Look for elements with the specified string.
    select : dict
        Select which fields to return.
    filter_type : str
        Type of node (worker/master).
    q : str
        Query for filtering a list of results.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    result : dict
        Data from each node.
    """
    if q:
        # If exists q parameter, apply limit and offset after filtering by q.
        arguments = {
            'filter_node': filter_node,
            'offset': 0,
            'limit': common.DATABASE_LIMIT,
            'sort': sort,
            'search': search,
            'select': select,
            'filter_type': filter_type,
            'distinct': distinct,
        }
    else:
        arguments = {
            'filter_node': filter_node,
            'offset': offset,
            'limit': limit,
            'sort': sort,
            'search': search,
            'select': select,
            'filter_type': filter_type,
            'distinct': distinct,
        }

    response = await lc.execute(command=b'get_nodes', data=json.dumps(arguments).encode())
    result = json.loads(response, object_hook=as_wazuh_object)

    if isinstance(result, Exception):
        raise result

    if q:
        result['items'] = filter_array_by_query(q, result['items'])
        # Get totalItems after applying q filter.
        result['totalItems'] = len(result['items'])
        # Apply offset and limit filters.
        result['items'] = result['items'][offset : offset + limit]

    return result


async def get_node(lc: local_client.LocalClient, filter_node=None, select=None):
    """Get basic information of one cluster node.

    Parameters
    ----------
    lc : LocalClient object
        LocalClient with which to send the 'get_nodes' request.
    filter_node : str, list
        Node to return.
    select : dict
        Select which fields to return (separated by comma).

    Returns
    -------
    result : dict
        Data of the node.
    """
    arguments = {
        'filter_node': filter_node,
        'offset': 0,
        'limit': common.DATABASE_LIMIT,
        'sort': None,
        'search': None,
        'select': select,
        'filter_type': 'all',
    }

    response = await lc.execute(command=b'get_nodes', data=json.dumps(arguments).encode())
    node_info_array = json.loads(response, object_hook=as_wazuh_object)

    if isinstance(node_info_array, Exception):
        raise node_info_array

    if len(node_info_array['items']) > 0:
        return node_info_array['items'][0]
    else:
        return {}


async def get_health(lc: local_client.LocalClient, filter_node=None):
    """Get nodes and synchronization information.

    Parameters
    ----------
    lc : LocalClient object
        LocalClient with which to send the 'get_nodes' request.
    filter_node : str, list
        Node to return.

    Returns
    -------
    result : dict
        Basic information of each node and synchronization process related information.
    """
    response = await lc.execute(command=b'get_health', data=json.dumps(filter_node).encode())
    result = json.loads(response, object_hook=as_wazuh_object)

    if isinstance(result, Exception):
        raise result

    return result


async def get_system_nodes():
    """Get the name of all the cluster nodes.

    Returns
    -------
    list
        Name of each cluster node.
    """
    try:
        lc = local_client.LocalClient()
        result = await get_nodes(lc)
        return [node['name'] for node in result['items']]
    except WazuhInternalError as e:
        raise e
