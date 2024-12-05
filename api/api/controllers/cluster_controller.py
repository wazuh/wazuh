# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion import request
from connexion.lifecycle import ConnexionResponse

import wazuh.cluster as cluster
import wazuh.manager as manager
from api.controllers.util import json_response, XML_CONTENT_TYPE
from api.models.base_model_ import Body
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh.core.cluster.control import get_system_nodes
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.results import AffectedItemsWazuhResult

logger = logging.getLogger('wazuh-api')



async def get_cluster_nodes(pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                            limit: int = None, sort: str = None, search: str = None, select: str = None,
                            nodes_list: str = None, q: str = None, distinct: bool = False) -> ConnexionResponse:
    """Get information about all nodes in the cluster or a list of them.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : list
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
        to list in ascending or descending order.
    search : str
        Look for elements with the specified string.
    nodes_list : str
        List of node IDs.
    q : str
        Query to filter results by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    # Get type parameter from query
    type_ = request.query_params.get('type', 'all')

    f_kwargs = {'filter_node': nodes_list,
                'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'select': select,
                'filter_type': type_,
                'q': q,
                'distinct': distinct}

    nodes = raise_if_exc(await get_system_nodes())
    dapi = DistributedAPI(f=cluster.get_nodes_info,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          local_client_arg='lc',
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          nodes=nodes
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_healthcheck(pretty: bool = False, wait_for_complete: bool = False,
                          nodes_list: str = None) -> ConnexionResponse:
    """Get cluster healthcheck.

    Returns cluster healthcheck information for all nodes or a list of them. Such information includes last keep alive,
    last synchronization time and number of agents reporting on each node.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    nodes_list : str
        List of node IDs.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'filter_node': nodes_list}

    nodes = raise_if_exc(await get_system_nodes())
    dapi = DistributedAPI(f=cluster.get_health_nodes,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          local_client_arg='lc',
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          nodes=nodes
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_status(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Get cluster status.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {}
    dapi = DistributedAPI(f=cluster.get_status_json,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_status_node(node_id: str, pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Get a specified node's Wazuh daemons status.

    Parameters
    ----------
    node_id : str
        Cluster node name.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'node_id': node_id}

    nodes = raise_if_exc(await get_system_nodes())
    dapi = DistributedAPI(f=manager.get_status,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          nodes=nodes
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_info_node(node_id: str, pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Get a specified node's information.

    Returns basic information about a specified node such as version, compilation date, installation path.

    Parameters
    ----------
    node_id : str
        Cluster node name.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'node_id': node_id}

    nodes = raise_if_exc(await get_system_nodes())
    dapi = DistributedAPI(f=manager.get_basic_info,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          nodes=nodes
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_configuration_node(node_id: str, pretty: bool = False, wait_for_complete: bool = False,
                                 section: str = None, field: str = None,
                                 raw: bool = False) -> ConnexionResponse:
    """Get a specified node's configuration (ossec.conf).

    Parameters
    ----------
    node_id : str
        Cluster node name.
    pretty : bool
        Show results in human-readable format. It only works when `raw` is False (JSON format). Default `False`
    wait_for_complete : bool
        Disable response timeout or not. Default `False`
    section : str
        Indicates the wazuh configuration section.
    field : str
        Indicates a section child.
    raw : bool, optional
        Whether to return the file content in raw or JSON format. Default `False`

    Returns
    -------
    ConnexionResponse
        Depending on the `raw` parameter, it will return a ConnexionResponse object:
            raw=True            -> ConnexionResponse (application/xml)
            raw=False (default) -> ConnexionResponse (application/json)
        If any exception was raised, it will return a ConnexionResponse with details.
    """
    f_kwargs = {'node_id': node_id,
                'section': section,
                'field': field,
                'raw': raw}

    nodes = raise_if_exc(await get_system_nodes())
    dapi = DistributedAPI(f=manager.read_ossec_conf,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          nodes=nodes
                          )
    data = raise_if_exc(await dapi.distribute_function())

    if isinstance(data, AffectedItemsWazuhResult):
        response = json_response(data, pretty=pretty)
    else:
        response = ConnexionResponse(body=data["message"],
                                     content_type=XML_CONTENT_TYPE)
    return response


async def get_daemon_stats_node(node_id: str, pretty: bool = False, wait_for_complete: bool = False):
    """Get Wazuh statistical information from the specified daemons of a specified cluster node.

    Parameters
    ----------
    node_id : str
        Cluster node name.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    """
    raise NotImplementedError


async def get_log_node(node_id: str, pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                       limit: int = None, sort: str = None, search: str = None, tag: str = None, level: str = None,
                       q: str = None, select: str = None, distinct: bool = False) -> ConnexionResponse:
    """Get a specified node's wazuh logs.

    Returns the last 2000 wazuh log entries in node {node_id}.

    Parameters
    ----------
    node_id : str
        Cluster node name.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
        to list in ascending or descending order.
    search : str
        Look for elements with the specified string.
    tag : str
        Filters by category/tag of log.
    level : str
        Filters by log level.
    q : str
        Query to filter results by.
    select : str
        Select which fields to return (separated by comma).
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'node_id': node_id,
                'offset': offset,
                'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['timestamp'],
                'sort_ascending': False if sort is None or parse_api_param(sort, 'sort')['order'] == 'desc' else True,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'tag': tag,
                'level': level,
                'q': q,
                'select': select,
                'distinct': distinct}

    nodes = raise_if_exc(await get_system_nodes())
    dapi = DistributedAPI(f=manager.ossec_log,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          nodes=nodes
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_log_summary_node(node_id: str, pretty: bool = False,
                               wait_for_complete: bool = False) -> ConnexionResponse:
    """Get a summary of a specified node's wazuh logs.

    Parameters
    ----------
    node_id : str
        Cluster node name.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'node_id': node_id}

    nodes = raise_if_exc(await get_system_nodes())
    dapi = DistributedAPI(f=manager.ossec_log_summary,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          nodes=nodes
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def put_restart(pretty: bool = False, wait_for_complete: bool = False,
                      nodes_list: str = '*') -> ConnexionResponse:
    """Restarts all nodes in the cluster or a list of them.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    nodes_list : str
        List of node IDs.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'node_list': nodes_list}

    nodes = raise_if_exc(await get_system_nodes())
    dapi = DistributedAPI(f=manager.restart,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=nodes_list == '*',
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          nodes=nodes
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_conf_validation(pretty: bool = False, wait_for_complete: bool = False,
                              nodes_list: str = '*') -> ConnexionResponse:
    """Check whether the Wazuh configuration in a list of cluster nodes is correct or not.


    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    nodes_list : str
        List of node IDs.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'node_list': nodes_list}

    nodes = raise_if_exc(await get_system_nodes())
    dapi = DistributedAPI(f=manager.validation,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=nodes_list == '*',
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          nodes=nodes
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def update_configuration(node_id: str, body: bytes, pretty: bool = False,
                               wait_for_complete: bool = False) -> ConnexionResponse:
    """Update Wazuh configuration (ossec.conf) in node node_id.

    Parameters
    ----------
    node_id : str
        Node ID.
    body : bytes
        New content for the Wazuh configuration (ossec.conf).
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    # Parse body to utf-8
    Body.validate_content_type(request, expected_content_type='application/octet-stream')
    parsed_body = Body.decode_body(body, unicode_error=1911, attribute_error=1912)

    f_kwargs = {'node_id': node_id,
                'new_conf': parsed_body}

    nodes = raise_if_exc(await get_system_nodes())
    dapi = DistributedAPI(f=manager.update_ossec_conf,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          nodes=nodes
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
