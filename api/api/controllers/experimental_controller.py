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
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
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
def get_cis_cat_results(pretty=False, wait_for_complete=False, offset=0, limit=None,
                        select=None, sort=None, search=None, benchmark=None, profile=None,
                        fail=None, error=None, notchecked=None, unknown=None, score=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param benchmark: Filters by benchmark
    :type benchmark: str
    :param profile: Filters by evaluated profile
    :type profile: str
    :param fail: Filters by failed checks
    :type fail: int
    :param error: Filters by encountered errors
    :type error: int
    :param notchecked: Filters by not checked
    :type notcheked: int
    :param unknown: Filters by unknown results.
    :type unknown: int
    :param score: Filters by final score
    :type score: int
    """
    # get pass parameter from query
    pass_ = connexion.request.args.get('pass', None)

    filters = {'benchmark': benchmark,
               'profile': profile,
               'fail': fail,
               'error': error,
               'notchecked': notchecked,
               'unknown': unknown,
               'score': score,
               'pass': pass_}

    f_kwargs = {'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters}

    dapi = DistributedAPI(f=ciscat.get_ciscat_results,
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
def get_hardware_info(pretty=False, wait_for_complete=False, offset=0,
                      limit=None, select=None, sort=None, search=None,
                      ram_free=None, ram_total=None, cpu_cores=None,
                      cpu_mhz=None, cpu_name=None, board_serial=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param ram_free: Filters by ram_free
    :type ram_free: str
    :param ram_total: Filters by ram_total
    :type ram_total: str
    :param cpu_cores: Filters by cpu_cores
    :type cpu_cores: str
    :param cpu_mhz: Filters by cpu_mhz
    :type cpu_mhz: str
    :param cpu_name: Filters by cpu_name
    :type cpu_name: str
    :param board_serial: Filters by board_serial
    :type board_serial: str
    """
    filters = {'ram_free': ram_free,
               'ram_total': ram_total,
               'cpu_cores': cpu_cores,
               'cpu_mhz': cpu_mhz,
               'cpu_name': cpu_name,
               'board_serial': board_serial}

    f_kwargs = {'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters}

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
def get_network_address_info(pretty=False, wait_for_complete=False,
    offset=0, limit=None, select=None, sort=None, search=None, iface_name=None,
    proto=None, address=None, broadcast=None, netmask=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param iface_name: Filters by interface name
    :type iface_name: str
    :param proto: Filters by IP protocol
    :type proto: str
    :param address: IP address associated with the network interface
    :type address: str
    :param broadcast: Filters by broadcast direction
    :type broadcast: str
    :param netmask: Filters by netmask
    :type netmask: str
    """
    filters = {'iface_name': iface_name,
               'proto': proto,
               'address': address,
               'broadcast': broadcast,
               'netmask': netmask}

    f_kwargs = {'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters}

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
def get_network_interface_info(pretty=False, wait_for_complete=False,
    offset=0, limit=None, select=None, sort=None, search=None, adapter=None,
    type=None, state=None, mtu=None, tx_packets=None, rx_packets=None,
    tx_bytes=None, rx_bytes=None, tx_errors=None, rx_errors=None,
    tx_dropped=None, rx_dropped=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param adapter: Filters by adapter
    :type adapter: str
    :param type: Filters by type
    :type type: str
    :params state: Filters by state
    :type state: str
    :params mtu: Filters by mtu
    :type mtu: str
    :params tx_packets: Filters by tx_packets
    :type tx_packets: str
    :param rx_packets: Filters by rx_packets
    :type rx_packets: str
    :param tx_bytes: Filters by tx_bytes
    :type tx_bytes: str
    :param rx_bytes: Filters by rx_bytes
    :type rx_bytes: str
    :params tx_errors: Filters by tx_errors
    :type tx_errors: str
    :params rx_errors: Filters by rx_errors
    :type rx_errors: str
    :params tx_dropped: Filters by xx_dropped
    :type tx_droppred: str
    :params rx_dropped: Filters by rx_dropped
    :type rx_droppred: str
    """
    # get type parameter from query
    type_ = connexion.request.args.get('type', None)

    filters = {'adapter': adapter,
               'type': type_,
               'state': state,
               'mtu': mtu,
               'tx_packets': tx_packets,
               'rx_packets': rx_packets,
               'tx_bytes': tx_bytes,
               'rx_bytes': rx_bytes,
               'tx_errors': tx_errors,
               'rx_errors': rx_errors,
               'tx_dropped': tx_dropped,
               'rx_dropped': rx_dropped}

    f_kwargs = {'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters}

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
def get_network_protocol_info(pretty=False, wait_for_complete=False,
    offset=0, limit=None, select=None, sort=None, search=None, iface=None,
    gateway=None, dhcp=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param iface: Filters by iface
    :type iface: str
    :param type: Filters by type
    :type type: str
    :param gateway: Filters by gateway
    :type gateway: str
    :param dhcp: Filters by dhcp
    :type dhcp: str
    """
    # get type parameter from query
    type_ = connexion.request.args.get('type', None)

    filters = {'iface': iface,
               'type': type_,
               'gateway': gateway,
               'dhcp': dhcp}

    f_kwargs = {'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters}

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
def get_os_info(pretty=False, wait_for_complete=False, offset=0, limit=None,
                select=None, sort=None, search=None, os_name=None,
                architecture=None, os_version=None, version=None,
                release=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param os_name: Filters by os_name
    :type os_name: str
    :param architecture: Filters by architecture
    :type architecture: str
    :param os_version: Filters by os_version
    :type os_version: str
    :param version: Filters by version
    :type version: str
    :param release: Filters by release
    :type release: str
    """
    filters = {'os_name': os_name,
               'architecture': architecture,
               'os_version': os_version,
               'version': version,
               'release': release}

    f_kwargs = {'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters}

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
def get_packages_info(pretty=False, wait_for_complete=False, offset=0,
                      limit=None, select=None, sort=None, search=None,
                      vendor=None, name=None, architecture=None, format=None,
                      version=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param vendor: Filters by vendor
    :type vendor: str
    :param name: Filters by name
    :type name: str
    :param architecture: Filters by architecture
    :type architecture: str
    :param format: Filters by package format
    :type format: str
    :param version: Filters by format
    :type version: str
    """
    # get format parameter from query
    format_ = connexion.request.args.get('format', None)

    filters = {'vendor': vendor,
               'name': name,
               'architecture': architecture,
               'format': format_,
               'version': version}

    f_kwargs = {'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters}

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
def get_ports_info(pretty=False, wait_for_complete=False,
    offset=0, limit=None, select=None, sort=None, search=None, pid=None,
    protocol=None, local_ip=None, local_port=None, remote_ip=None,
    tx_queue=None, state=None, process=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param pid: Filters by pid
    :type pid: str
    :param protocol: Filters by protocol
    :type protocol: str
    :param local_ip: Filters by local IP
    :type local_ip: str
    :param local_port: Filters by local port
    :type local_port: str
    :param remote_ip Filters by remote IP
    :type remote_ip: str
    :param tx_queue: Filters by tx_queue
    :type tx_queue: str
    :param state: Filters by state
    :type state: str
    :param process: Filters by process
    :type process: str
    """
    filters = {'pid': pid,
               'protocol': protocol,
               'local_ip': local_ip,
               'local_port': local_port,
               'remote_ip': remote_ip,
               'tx_queue': tx_queue,
               'state': state,
               'process': process}

    f_kwargs = {'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters}

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
def get_processes_info(pretty=False, wait_for_complete=False,
    offset=0, limit=None, select=None, sort=None, search=None, process_pid=None,
    process_state=None, ppid=None, egroup=None, euser=None, fgroup=None,
    process_name=None, nlwp=None, pgrp=None, priority=None, rgroup=None,
    ruser=None, sgroup=None, suser=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param process_pid: Filters by process pid
    :type process_pid: str
    :param process_state: Filters by process state
    :type process_state: str
    :param ppid: Filters by process parent pid
    :type ppid: str
    :param egroup: Filters by process egroup
    :type egroup: str
    :param euser Filters by process euser
    :type euser: str
    :param fgroup: Filters by process fgroup
    :type fgroup: str
    :param name: Filters by process name
    :type name: str
    :param nlwp: Filters by process nlwp
    :type nlwp: str
    :param pgrp: Filters by process pgrp
    :type pgrp: str
    :param priority: Filters by process priority
    :type priority: str
    :param rgroup: Filters by process rgroup
    :type rgroup: str
    :param ruser: Filters by process ruser
    :type ruser: str
    :param sgroup: Filters by process sgroup
    :type sgroup: str
    :param suser: Filters by process suser
    :type suser: str
    """
    filters = {'process_state': process_state,
               'process_pid': process_pid,
               'ppid': ppid,
               'egroup': egroup,
               'euser': euser,
               'fgroup': fgroup,
               'process_name': process_name,
               'nlwp': nlwp,
               'pgrp': pgrp,
               'priority': priority,
               'rgroup': rgroup,
               'ruser': ruser,
               'sgroup': sgroup,
               'suser': suser}

    f_kwargs = {'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters}

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
