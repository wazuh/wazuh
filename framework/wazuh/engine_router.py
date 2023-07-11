# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Optional, List

from wazuh.core.wazuh_socket import WazuhSocketJSON, create_wazuh_socket_message
from wazuh.core.results import WazuhResult
from wazuh.core.exception import WazuhInternalError, WazuhResourceNotFound, WazuhNotAcceptable
from wazuh.core.utils import process_array
from wazuh.core.common import ENGINE_SOCKET

# TODO Redefine HARDCODED values
HARDCODED_ORIGIN_NAME = "routes"
HARDCODED_ORIGIN_MODULE = "routes"


def get_routes(limit: int, name: Optional[str] = None, select: Optional[List] = None, sort_by: dict = None,
               sort_ascending: bool = True, search_text: str = None, complementary_search: bool = False,
               offset: int = 0, ):
    """
    Retrieves routes based on the specified parameters.

    Parameters
    ---------
    limit: int
        Maximum number of routes to retrieve.
    name: Optional[str]
        Name of the route.
    select: Optional[str]
        Fields to return (separated by comma).
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order.
    search_text : str
        Find items with the specified string.
    complementary_search : bool
        If True, only results NOT containing `search_text` will be returned. If False, only results that contains
        `search_text` will be returned.
    offset: int
        Number of elements to skip before returning the collection.

    Returns
    ---------
    WazuhResult
        WazuhResult with the results of the command
    """
    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    if name:
        msg = create_wazuh_socket_message(origin, 'router.route/get', {'name': name})
    else:
        msg = create_wazuh_socket_message(origin, 'router.table/get', {})

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        if name and result['error'] == 'Route not found':
            raise WazuhResourceNotFound(9004)
        else:
            raise WazuhInternalError(9002)

    if name:
        final_result = result['rute']
    else:
        final_result = process_array(result['table'], limit=limit, offset=offset, select=select, sort_by=sort_by,
                                     sort_ascending=sort_ascending, search_text=search_text,
                                     complementary_search=complementary_search)['items']

    return WazuhResult({'data': final_result})


def create_route(name: str, filter: str, policy: str, priority: int):
    """
    Creates a new route

    Parameters
    ---------
    name: str
        Name of the new route to create.
    filter: str
        Filter of the new route.
    policy: str
        Policy of the new route.
    priority:
        Priority of the new route.


    Returns
    ---------
    WazuhResult
        WazuhResult with the results of the command
    """
    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    route = {'route': {'name': name, 'filter': filter, 'policy': policy, 'priority': priority}}
    msg = create_wazuh_socket_message(origin, 'router.route/post', route)

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        if result['error'] == f"Route '{name}' already exists":
            raise WazuhNotAcceptable(9006)
        elif result['error'] == f"Priority '{priority}' already taken":
            raise WazuhNotAcceptable(9005)
        elif result['error'] == f"Policy '{policy}' already exists":
            raise WazuhNotAcceptable(9007)
        elif "Invalid policy name" in result['error']:
            raise WazuhNotAcceptable(9008, extra_message=result['error'])
        else:
            raise WazuhInternalError(9002)

    return WazuhResult({'message': result['status']})


def update_route(name: str, priority: int):
    """
    Updates a route priority.

    Parameters
    ---------
    name: str
        Name of the existing route.
    priority:
        The new priority value.

    Returns
    ---------
    WazuhResult
        WazuhResult with the results of the command
    """
    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    msg = create_wazuh_socket_message(origin, 'router.route/patch', {'route': {'name': name, 'priority': priority}})

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        if result['error'] == 'Route not found':
            raise WazuhResourceNotFound(9004)
        elif result['error'] == f"Priority '{priority}' already taken":
            raise WazuhNotAcceptable(9005)
        else:
            raise WazuhInternalError(9002)

    return WazuhResult({'message': result['status']})


def delete_route(name: str):
    """
    Deletes a route

    Parameters
    ---------
    name: str
        Name of the route to delete.

    Returns
    ---------
    WazuhResult
        WazuhResult with the results of the command
    """
    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    msg = create_wazuh_socket_message(origin, 'router.route/delete', {'name': name})

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        if result['error'] == 'Route not found':
            raise WazuhResourceNotFound(9004)
        else:
            raise WazuhInternalError(9002)

    return WazuhResult({'message': result['status']})
