# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import connexion
import logging

from api.models.base_model_ import Data
from api.util import remove_nones_to_dict, exception_handler, parse_api_param, raise_if_exc
from wazuh.cluster.dapi.dapi import DistributedAPI
import wazuh.ciscat as ciscat
import wazuh.syscheck as syscheck
import wazuh.syscollector as syscollector


loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def clear_syscheck_database(pretty=False, wait_for_complete=False):
    """ Clear the syscheck database for all agents.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return: Message
    """
    f_kwargs = {'all_agents': True}
    dapi = DistributedAPI(f=syscheck.clear,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_cis_cat_results(pretty=False, wait_for_complete=False, offset=0, limit=None, select=None, sort=None,
                        search=None, benchmark=None, profile=None, fail=None, error=None, notchecked=None, unknown=None,
                        score=None):
    """ Get ciscat results info from all agents.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
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
    :return: Data
    """
    f_kwargs = {
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
            'pass': connexion.request.args.get('pass', None)
                }
            }

    dapi = DistributedAPI(f=ciscat.get_ciscat_experimental,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_hardware_info(pretty=False, wait_for_complete=False, offset=0, limit=None, select=None, sort=None, search=None,
                      ram_free=None, ram_total=None, cpu_cores=None, cpu_mhz=None, cpu_name=None, board_serial=None):
    """ Get hardware info from all agents.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param ram_free: Filters by ram_free
    :param ram_total: Filters by ram_total
    :param cpu_cores: Filters by cpu_cores
    :param cpu_mhz: Filters by cpu_mhz
    :param cpu_name: Filters by cpu_name
    :param board_serial: Filters by board_serial
    :return: Data
    """
    f_kwargs = {
        'offset': offset,
        'limit': limit,
        'select': select,
        'sort': parse_api_param(sort, 'sort'),
        'search': parse_api_param(search, 'search'),
        'filters': {
            'ram_free': ram_free,
            'ram_total': ram_total,
            'cpu_cores': cpu_cores,
            'cpu_mhz': cpu_mhz,
            'cpu_name': cpu_name,
            'board_serial': board_serial
                }
        }

    dapi = DistributedAPI(f=syscollector.get_hardware,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_network_address_info(pretty=False, wait_for_complete=False, offset=0, limit=None, select=None, sort=None,
                             search=None, iface_name=None, proto=None, address=None, broadcast=None, netmask=None):
    """ Get the IPv4 and IPv6 addresses associated to all network interfaces

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
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
    :return: Data
    """
    f_kwargs = {
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
                }
        }

    dapi = DistributedAPI(f=syscollector.get_netaddr,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_network_interface_info(pretty=False, wait_for_complete=False, offset=0, limit=None, select=None, sort=None,
                               search=None, adapter=None, state=None, mtu=None):
    """ Get all network interfaces from all agents.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param adapter: Filters by adapter
    :param state: Filters by state
    :param mtu: Filters by mtu
    :return: Data
    """
    filters = {
        'adapter': adapter,
        'type': connexion.request.args.get('type', None),
        'state': state,
        'mtu': mtu
        }
    # Add nested fields to kwargs filters
    nested = ['tx.packets', 'rx.packets', 'tx.bytes', 'rx.bytes', 'tx.errors', 'rx.errors', 'tx.dropped', 'rx.dropped']
    for field in nested:
        filters[field] = connexion.request.args.get(field, None)

    f_kwargs = {
        'offset': offset,
        'limit': limit,
        'select': select,
        'sort': parse_api_param(sort, 'sort'),
        'search': parse_api_param(search, 'search'),
        'filters': filters
        }

    dapi = DistributedAPI(f=syscollector.get_netiface,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_network_protocol_info(pretty=False, wait_for_complete=False, offset=0, limit=None, select=None, sort=None,
                              search=None, iface=None, gateway=None, dhcp=None):
    """ Get network protocol info from all agents.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param iface: Filters by iface
    :param gateway: Filters by gateway
    :param dhcp: Filters by dhcp
    :return: Data
    """
    f_kwargs = {
        'offset': offset,
        'limit': limit,
        'select': select,
        'sort': parse_api_param(sort, 'sort'),
        'search': parse_api_param(search, 'search'),
        'filters': {
            'iface': iface,
            'type': connexion.request.args.get('type', None),
            'gateway': gateway,
            'dhcp': dhcp
            }
        }

    dapi = DistributedAPI(f=syscollector.get_netproto,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_os_info(pretty=False, wait_for_complete=False, offset=0, limit=None, select=None, sort=None, search=None,
                os_name=None, architecture=None, os_version=None, version=None, release=None):
    """ Get OS info from all agents.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
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
    :return: Data
    """
    f_kwargs = {
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
            }
        }

    dapi = DistributedAPI(f=syscollector.get_os,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_packages_info(pretty=False, wait_for_complete=False, offset=0, limit=None, select=None, sort=None, search=None,
                      vendor=None, name=None, architecture=None, version=None):
    """ Get packages info from all agents.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
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
    :return: Data
    """
    f_kwargs = {
        'offset': offset,
        'limit': limit,
        'select': select,
        'sort': parse_api_param(sort, 'sort'),
        'search': parse_api_param(search, 'search'),
        'filters': {
            'vendor': vendor,
            'name': name,
            'architecture': architecture,
            'format': connexion.request.args.get('format', None),
            'version': version
            }
        }

    dapi = DistributedAPI(f=syscollector.get_packages,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_ports_info(pretty=False, wait_for_complete=False, offset=0, limit=None, select=None, sort=None, search=None,
                   pid=None, protocol=None, tx_queue=None, state=None, process=None):
    """ Get ports info from all agents.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
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
    :return: Data
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
        filters[field] = connexion.request.args.get(field, None)

    f_kwargs = {
        'offset': offset,
        'limit': limit,
        'select': select,
        'sort': parse_api_param(sort, 'sort'),
        'search': parse_api_param(search, 'search'),
        'filters': filters
         }

    dapi = DistributedAPI(f=syscollector.get_ports,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_processes_info(pretty=False, wait_for_complete=False, offset=0, limit=None, select=None, sort=None, search=None,
                       pid=None, state=None, ppid=None, egroup=None, euser=None, fgroup=None, name=None, nlwp=None,
                       pgrp=None, priority=None, rgroup=None, ruser=None, sgroup=None, suser=None):
    """ Get processes info from all agents.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
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
    :return: Data
    """
    f_kwargs = {
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
            }
        }

    dapi = DistributedAPI(f=syscollector.get_processes,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200
