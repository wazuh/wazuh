# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from functools import wraps

from aiohttp import web

import wazuh.ciscat as ciscat
import wazuh.syscheck as syscheck
import wazuh.syscollector as syscollector
from api import configuration
from api.encoder import dumps, prettify
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.exception import WazuhResourceNotFound

logger = logging.getLogger('wazuh-api')


def check_experimental_feature_value(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not configuration.api_conf['experimental_features']:
            raise_if_exc(WazuhResourceNotFound(code=1122))
        else:
            return func(*args, **kwargs)
    return wrapper


@check_experimental_feature_value
async def clear_syscheck_database(request, pretty=False, wait_for_complete=False, agents_list=None):
    """ Clear the syscheck database for all agents.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agents_list: List of agent's IDs.
    :return: AllItemsResponseAgentIDs
    """
    if 'all' in agents_list:
        agents_list = '*'

    f_kwargs = {'agent_list': agents_list}

    dapi = DistributedAPI(f=syscheck.clear,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@check_experimental_feature_value
async def get_cis_cat_results(request, pretty=False, wait_for_complete=False, agents_list='*', offset=0, limit=None,
                              select=None, sort=None, search=None, benchmark=None, profile=None, fail=None, error=None,
                              notchecked=None, unknown=None, score=None):
    """ Get ciscat results info from all agents or a list of them.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agents_list: List of agent's IDs.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param benchmark: Filters by benchmark
    :param profile: Filters by evaluated profile
    :param fail: Filters by failed checks
    :param error: Filters by encountered errors
    :param notchecked: Filters by not checked
    :param unknown: Filters by unknown results.
    :param score: Filters by final score
    :return: AllItemsResponseCiscatResult
    """
    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': {
                    'benchmark': benchmark,
                    'profile': profile,
                    'fail': fail,
                    'error': error,
                    'notchecked': notchecked,
                    'unknown': unknown,
                    'score': score,
                    'pass': request.query.get('pass', None)
                }
                }

    dapi = DistributedAPI(f=ciscat.get_ciscat_results,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@check_experimental_feature_value
async def get_hardware_info(request, pretty=False, wait_for_complete=False, agents_list='*', offset=0, limit=None,
                            select=None, sort=None, search=None, board_serial=None):
    """ Get hardware info from all agents or a list of them.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agents_list: List of agent's IDs.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param board_serial: Filters by board_serial
    :return: AllItemsResponseSyscollectorHardware
    """
    filters = {
        'board_serial': board_serial
    }
    # Add nested fields to kwargs filters
    nested = ['ram.free', 'ram.total', 'cpu.cores', 'cpu.mhz', 'cpu.name']
    for field in nested:
        filters[field] = request.query.get(field, None)
    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters,
                'element_type': 'hardware'
                }

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@check_experimental_feature_value
async def get_network_address_info(request, pretty=False, wait_for_complete=False, agents_list='*', offset=0,
                                   limit=None, select=None, sort=None, search=None, iface_name=None, proto=None,
                                   address=None, broadcast=None, netmask=None):
    """ Get the IPv4 and IPv6 addresses associated to all network interfaces

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agents_list: List of agent's IDs.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param iface_name: Filters by interface name
    :param proto: Filters by IP protocol
    :param address: IP address associated with the network interface
    :param broadcast: Filters by broadcast direction
    :param netmask: Filters by netmask
    :return: AllItemsResponseSyscollectorNetwork
    """
    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': {
                    'iface_name': iface_name,
                    'proto': proto,
                    'address': address,
                    'broadcast': broadcast,
                    'netmask': netmask
                },
                'element_type': 'netaddr'
                }

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@check_experimental_feature_value
async def get_network_interface_info(request, pretty=False, wait_for_complete=False, agents_list='*', offset=0,
                                     limit=None, select=None, sort=None, search=None, adapter=None, state=None,
                                     mtu=None):
    """ Get all network interfaces from all agents or a list of them.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agents_list: List of agent's IDs.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param adapter: Filters by adapter
    :param state: Filters by state
    :param mtu: Filters by mtu
    :return: AllItemsResponseSyscollectorInterface
    """
    filters = {
        'adapter': adapter,
        'type': request.query.get('type', None),
        'state': state,
        'mtu': mtu
    }
    # Add nested fields to kwargs filters
    nested = ['tx.packets', 'rx.packets', 'tx.bytes', 'rx.bytes', 'tx.errors', 'rx.errors', 'tx.dropped', 'rx.dropped']
    for field in nested:
        filters[field] = request.query.get(field, None)

    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters,
                'element_type': 'netiface'
                }

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@check_experimental_feature_value
async def get_network_protocol_info(request, pretty=False, wait_for_complete=False, agents_list='*', offset=0,
                                    limit=None, select=None, sort=None, search=None, iface=None, gateway=None,
                                    dhcp=None):
    """ Get network protocol info from all agents or a list of them.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agents_list: List of agent's IDs.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param iface: Filters by iface
    :param gateway: Filters by gateway
    :param dhcp: Filters by dhcp
    :return: AllItemsResponseSyscollectorProtocol
    """
    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': {
                    'iface': iface,
                    'type': request.query.get('type', None),
                    'gateway': gateway,
                    'dhcp': dhcp
                },
                'element_type': 'netproto'
                }

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@check_experimental_feature_value
async def get_os_info(request, pretty=False, wait_for_complete=False, agents_list='*', offset=0, limit=None,
                      select=None, sort=None, search=None, os_name=None, architecture=None, os_version=None,
                      version=None, release=None):
    """ Get OS info from all agents or a list of them.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agents_list: List of agent's IDs.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param os_name: Filters by os_name
    :param architecture: Filters by architecture
    :param os_version: Filters by os_version
    :param version: Filters by version
    :param release: Filters by release
    :return: AllItemsResponseSyscollectorOS
    """
    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': {
                    'os_name': os_name,
                    'architecture': architecture,
                    'os_version': os_version,
                    'version': version,
                    'release': release
                },
                'element_type': 'os'
                }

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@check_experimental_feature_value
async def get_packages_info(request, pretty=False, wait_for_complete=False, agents_list='*', offset=0, limit=None,
                            select=None,
                            sort=None, search=None, vendor=None, name=None, architecture=None, version=None):
    """ Get packages info from all agents or a list of them.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agents_list: List of agent's IDs.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param vendor: Filters by vendor
    :param name: Filters by name
    :param architecture: Filters by architecture
    :param version: Filters by format
    :return: AllItemsResponseSyscollectorPackages
    """
    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': {
                    'vendor': vendor,
                    'name': name,
                    'architecture': architecture,
                    'format': request.query.get('format', None),
                    'version': version
                },
                'element_type': 'packages'
                }

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@check_experimental_feature_value
async def get_ports_info(request, pretty=False, wait_for_complete=False, agents_list='*', offset=0, limit=None,
                         select=None, sort=None, search=None, pid=None, protocol=None, tx_queue=None, state=None,
                         process=None):
    """ Get ports info from all agents or a list of them.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agents_list: List of agent's IDs.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param pid: Filters by pid
    :param protocol: Filters by protocol
    :param tx_queue: Filters by tx_queue
    :param state: Filters by state
    :param process: Filters by process
    :return: AllItemsResponseSyscollectorPorts
    """
    filters = {
        'pid': pid,
        'protocol': protocol,
        'tx_queue': tx_queue,
        'state': state,
        'process': process
    }
    # Add nested fields to kwargs filters
    nested = ['local.ip', 'local.port', 'remote.ip']
    for field in nested:
        filters[field] = request.query.get(field, None)

    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters,
                'element_type': 'ports'
                }

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@check_experimental_feature_value
async def get_processes_info(request, pretty=False, wait_for_complete=False, agents_list='*', offset=0, limit=None,
                             select=None, sort=None, search=None, pid=None, state=None, ppid=None, egroup=None,
                             euser=None, fgroup=None, name=None, nlwp=None, pgrp=None, priority=None, rgroup=None,
                             ruser=None, sgroup=None, suser=None):
    """ Get processes info from all agents or a list of them.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agents_list: List of agent's IDs.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param pid: Filters by process pid
    :param state: Filters by process state
    :param ppid: Filters by process parent pid
    :param egroup: Filters by process egroup
    :param euser Filters by process euser
    :param fgroup: Filters by process fgroup
    :param name: Filters by process name
    :param nlwp: Filters by process nlwp
    :param pgrp: Filters by process pgrp
    :param priority: Filters by process priority
    :param rgroup: Filters by process rgroup
    :param ruser: Filters by process ruser
    :param sgroup: Filters by process sgroup
    :param suser: Filters by process suser
    :return: AllItemsResponseSyscollectorProcesses
    """
    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': {
                    'state': state,
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
                    'suser': suser
                },
                'element_type': 'processes'
                }

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@check_experimental_feature_value
async def get_hotfixes_info(request, pretty=False, wait_for_complete=False, agents_list='*', offset=0, limit=None,
                            sort=None, search=None, select=None, hotfix=None):
    """ Get hotfixes info from all agents or a list of them.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agents_list: List of agent's IDs.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/. at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param select: Select which fields to return (separated by comma)
    :param hotfix: Filters by hotfix in Windows agents
    :return:AllItemsResponseSyscollectorHotfixes
    """
    filters = {'hotfix': hotfix}

    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters,
                'element_type': 'hotfixes'}

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
