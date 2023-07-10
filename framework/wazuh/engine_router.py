# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Optional, List

from wazuh.core.wazuh_socket import WazuhSocketJSON, create_wazuh_socket_message
from wazuh.core.results import WazuhResult
from wazuh.core.utils import process_array
from wazuh.core.common import ENGINE_SOCKET

# TODO Redefine HARDCODED values
HARDCODED_ORIGIN_NAME = "routes"
HARDCODED_ORIGIN_MODULE = "routes"


def get_routes(limit: int, name: Optional[str] = None, select: Optional[List] = None, sort_by: dict = None,
               sort_ascending: bool = True, search_text: str = None, complementary_search: bool = False,
               offset: int = 0, ):
    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    if name:
        msg = create_wazuh_socket_message(origin, 'router.route/get', {'name': name})
    else:
        msg = create_wazuh_socket_message(origin, 'router.table/get', {})

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        #TODO Handle error
        pass

    if name:
        final_result = result['rute']
    else:
        final_result = process_array(result['table'], limit=limit, offset=offset, select=select, sort_by=sort_by,
                                     sort_ascending=sort_ascending, search_text=search_text,
                                     complementary_search=complementary_search)

    return WazuhResult({'data': final_result['items']})


def create_route(name: str, filter: str, policy: str, priority: int):
    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    route = {'route': {'name': name, 'filter': filter, 'policy': policy, 'priority': priority}}
    msg = create_wazuh_socket_message(origin, 'router.route/post', route)

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        #TODO Handle error
        pass

    return WazuhResult({'message': result['status']})


def update_route(name: str, priority: int):
    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    msg = create_wazuh_socket_message(origin, 'router.route/patch', {'route': {'name': name, 'priority': priority}})

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        #TODO Handle error
        pass

    return WazuhResult({'message': result['status']})


def delete_route(name: str):
    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    msg = create_wazuh_socket_message(origin, 'router.route/delete', {'name': name})

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        #TODO Handle error
        pass

    return WazuhResult({'message': result['status']})
