# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion import request
from connexion.lifecycle import ConnexionResponse

import wazuh.syscollector as syscollector
from api.controllers.util import json_response
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')


async def get_hardware_info(agent_id: str, pretty: bool = False, wait_for_complete: bool = False,
                            select: str = None) -> ConnexionResponse:
    """Get hardware info of an agent.

    Parameters
    ----------
    agent_id : str
        Agent ID.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    select : str
        Select which fields to return (separated by comma).

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'agent_list': [agent_id],
                'select': select,
                'element_type': 'hardware'}
    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_hotfix_info(agent_id: str, pretty: bool = False, wait_for_complete: bool = False,
                          offset: int = 0, limit: int = None, sort: str = None, search: str = None, select: str = None,
                          hotfix: str = None, q: str = None, distinct: bool = False) -> ConnexionResponse:
    """Get info about an agent's hotfixes.

    Parameters
    ----------
    agent_id : str
        Agent ID.
    offset : int
        First element to return.
    limit : int
        Maximum number of elements to return.
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/. at the beginning to list in ascending
        or descending order.
    search : str
        Look for elements with the specified string.
    select : str
        Select which fields to return.
    hotfix : str
        Filters by hotfix in Windows agents.
    q : str
        Query to filter results by.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response.
    """

    filters = {'hotfix': hotfix}

    f_kwargs = {'agent_list': [agent_id],
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters,
                'element_type': 'hotfixes',
                'q': q,
                'distinct': distinct}

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_network_address_info(agent_id: str, pretty: bool = False, wait_for_complete: bool = False,
                                   offset: int = 0, limit: int = None, select: str = None, sort: str = None,
                                   search: str = None, iface: str = None, proto: str = None, address: str = None,
                                   broadcast: str = None, netmask: str = None, q: str = None,
                                   distinct: bool = False) -> ConnexionResponse:
    """Get network address info of an agent.

    Parameters
    ----------
    agent_id : str
        Agent ID.
    offset : int
        First element to return.
    limit : int
        Maximum number of elements to return.
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/. at the beginning to list in ascending
        or descending order.
    search : str
        Look for elements with the specified string.
    select : str
        Select which fields to return.
    q : str
        Query to filter results by.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    iface : str
        Filters by interface name.
    proto : str
        Filters by IP protocol.
    address : str
        IP address associated with the network interface.
    broadcast : str
        Filters by broadcast direction.
    netmask : str
        Filters by netmask.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    filters = {'iface': iface,
               'proto': proto,
               'address': address,
               'broadcast': broadcast,
               'netmask': netmask}

    f_kwargs = {'agent_list': [agent_id],
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters,
                'element_type': 'netaddr',
                'q': q,
                'distinct': distinct}

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_network_interface_info(agent_id: str, pretty: bool = False, wait_for_complete: bool = False,
                                     offset: int = 0, limit: int = None, select: str = None, sort: str = None,
                                     search: str = None, name: str = None, adapter: str = None, state: str = None,
                                     mtu: str = None, q: str = None, distinct: bool = False) -> ConnexionResponse:
    """Get network interface info of an agent.

    Parameters
    ----------
    agent_id : str
        Agent ID.
    offset : int
        First element to return.
    limit : int
        Maximum number of elements to return.
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/. at the beginning to list in ascending
        or descending order.
    search : str
        Look for elements with the specified string.
    select : str
        Select which fields to return.
    q : str
        Query to filter results by.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    name : str
        Name of the network interface.
    adapter : str
        Filters by adapter.
    state : str
        Filters by state.
    mtu : str
        Filters by mtu.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    filters = {'adapter': adapter,
               'type': request.query_params.get('type', None),
               'state': state,
               'name': name,
               'mtu': mtu}
    # Add nested fields to kwargs filters
    nested = ['tx.packets', 'rx.packets', 'tx.bytes', 'rx.bytes', 'tx.errors', 'rx.errors', 'tx.dropped', 'rx.dropped']
    for field in nested:
        filters[field] = request.query_params.get(field, None)

    f_kwargs = {'agent_list': [agent_id],
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters,
                'element_type': 'netiface',
                'q': q,
                'distinct': distinct}

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_network_protocol_info(agent_id: str, pretty: bool = False, wait_for_complete: bool = False,
                                    offset: int = 0, limit: int = None, select: str = None, sort: str = None,
                                    search: str = None, iface: str = None, gateway: str = None, dhcp: str = None,
                                    q: str = None, distinct: bool = False) -> ConnexionResponse:
    """Get network protocol info of an agent.

    Parameters
    ----------
    agent_id : str
        Agent ID.
    offset : int
        First element to return.
    limit : int
        Maximum number of elements to return.
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/. at the beginning to list in ascending
        or descending order.
    search : str
        Look for elements with the specified string.
    select : str
        Select which fields to return.
    q : str
        Query to filter results by.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    iface : str
        Filters by iface.
    gateway : str
        Filters by gateway.
    dhcp : str
        Filters by dhcp.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    filters = {'iface': iface,
               'type': request.query_params.get('type', None),
               'gateway': gateway,
               'dhcp': dhcp}

    f_kwargs = {'agent_list': [agent_id],
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters,
                'element_type': 'netproto',
                'q': q,
                'distinct': distinct}

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_os_info(agent_id: str, pretty: bool = False, wait_for_complete: bool = False,
                      select: str = None) -> ConnexionResponse:
    """Get OS info of an agent.

    Parameters
    ----------
    agent_id : str
        Agent ID.
    select : str
        Select which fields to return.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'agent_list': [agent_id],
                'select': select,
                'element_type': 'os'}

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_packages_info(agent_id: str, pretty: bool = False, wait_for_complete: bool = False,
                            offset: int = 0, limit: int = None, select: str = None, sort: str = None,
                            search: str = None, vendor: str = None, name: str = None, architecture: str = None,
                            version: str = None, q: str = None, distinct: bool = False) -> ConnexionResponse:
    """Get packages info of an agent.

    Parameters
    ----------
    agent_id : str
        Agent ID.
    offset : int
        First element to return.
    limit : int
        Maximum number of elements to return.
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/. at the beginning to list in ascending
        or descending order.
    search : str
        Look for elements with the specified string.
    select : str
        Select which fields to return.
    q : str
        Query to filter results by.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    vendor : str
        Filters by vendor.
    name : str
        Filters by name.
    architecture : str
        Filters by architecture.
    version : str
        Filters by version.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    filters = {'vendor': vendor,
               'name': name,
               'architecture': architecture,
               'format': request.query_params.get('format', None),
               'version': version}

    f_kwargs = {'agent_list': [agent_id],
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters,
                'element_type': 'packages',
                'q': q,
                'distinct': distinct}

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_ports_info(agent_id: str, pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                         limit: int = None, select: str = None, sort: str = None, search: str = None, pid: str = None,
                         protocol: str = None, tx_queue: str = None, state: str = None, process: str = None,
                         q: str = None, distinct: bool = False) -> ConnexionResponse:
    """Get ports info of an agent.

    Parameters
    ----------
    agent_id : str
        Agent ID.
    offset : int
        First element to return.
    limit : int
        Maximum number of elements to return.
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/. at the beginning to list in ascending
        or descending order.
    search : str
        Look for elements with the specified string.
    select : str
        Select which fields to return.
    q : str
        Query to filter results by.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    pid : str
        Filters by pid.
    protocol : str
        Filters by protocol.
    tx_queue : str
        Filters by tx_queue.
    state : str
        Filters by state.
    process : str
        Filters by process.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    filters = {'pid': pid,
               'protocol': protocol,
               'tx_queue': tx_queue,
               'state': state,
               'process': process}
    # Add nested fields to kwargs filters
    nested = ['local.ip', 'local.port', 'remote.ip']
    for field in nested:
        filters[field] = request.query_params.get(field, None)

    f_kwargs = {'agent_list': [agent_id],
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters,
                'element_type': 'ports',
                'q': q,
                'distinct': distinct}

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_processes_info(agent_id: str, pretty: bool = False, wait_for_complete: bool = False,
                             offset: int = 0, limit: int = None, select: str = None, sort: str = None,
                             search: str = None, pid: str = None, state: str = None, ppid: str = None,
                             egroup: str = None, euser: str = None, fgroup: str = None, name: str = None,
                             nlwp: str = None, pgrp: str = None, priority: str = None, rgroup: str = None,
                             ruser: str = None, sgroup: str = None, suser: str = None, q: str = None,
                             distinct: bool = False) -> ConnexionResponse:
    """Get processes info an agent.

    Parameters
    ----------
    agent_id : str
        Agent ID.
    offset : int
        First element to return.
    limit : int
        Maximum number of elements to return.
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/. at the beginning to list in ascending
        or descending order.
    search : str
        Look for elements with the specified string.
    select : str
        Select which fields to return.
    q : str
        Query to filter results by.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    pid : str
        Filters by pid.
    state : str
        Filters by process state.
    ppid : str
        Filters by process parent pid.
    egroup : str
        Filters by process egroup.
    euser : str
        Filters by process euser.
    fgroup : str
        Filters by process fgroup.
    name : str
        Filters by process name.
    nlwp : str
        Filters by process nlwp.
    pgrp : str
        Filters by process pgrp.
    priority : str
        Filters by process priority.
    rgroup : str
        Filters by process rgroup.
    ruser : str
        Filters by process ruser.
    sgroup : str
        Filters by process sgroup.
    suser : str
        Filters by process suser.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    filters = {'state': state,
               'pid': pid,
               'ppid': ppid,
               'egroup': egroup,
               'euser': euser,
               'fgroup': fgroup,
               'name': name,
               'nlwp': nlwp,
               'pgrp': pgrp,
               'priority': priority,
               'rgroup': rgroup,
               'ruser': ruser,
               'sgroup': sgroup,
               'suser': suser}

    f_kwargs = {'agent_list': [agent_id],
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters,
                'element_type': 'processes',
                'q': q,
               'distinct': distinct}

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
