# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging

from api.util import remove_nones_to_dict, exception_handler, parse_api_param
from wazuh.cluster.dapi.dapi import DistributedAPI
import wazuh.syscollector as syscollector
from ..util import raise_if_exc
from ..models.base_model_ import Data


loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def get_hardware_info(agent_id, pretty=False, wait_for_complete=False,
    select=None):
    """
    :param agent_id: Agent ID
    :type agent_id: str
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    """

    f_kwargs = {'agent_id': agent_id, 'select': select}

    dapi = DistributedAPI(f=syscollector.get_hardware_agent,
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
def get_network_address_info(agent_id, pretty=False, wait_for_complete=False,
    offset=0, limit=None, select=None, sort=None, search=None, iface=None,
    proto=None, address=None, broadcast=None, netmask=None):
    """
    :param agent_id: Agent ID
    :type agent_id: str
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
    :param iface: Filters by interface name
    :type iface: str
    :param proto: Filters by IP protocol
    :type proto: str
    :param address: IP address associated with the network interface
    :type address: str
    :param broadcast: Filters by broadcast direction
    :type broadcast: str
    :param netmask: Filters by netmask
    :type netmask: str
    """
    filters = {'iface': iface, 'proto': proto, 'address': address,
                'broadcast': broadcast, 'netmask': netmask}

    f_kwargs = {'agent_id': agent_id, 'offset': offset, 'limit': limit,
                'select': select, 'sort': parse_api_param(sort, 'sort'), 'search': parse_api_param(search, 'search'),
                'filters': filters}

    dapi = DistributedAPI(f=syscollector.get_netaddr_agent,
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
def get_network_interface_info(agent_id, pretty=False, wait_for_complete=False,
    offset=0, limit=None, select=None, sort=None, search=None, name=None,
    adapter=None, type=None, state=None, mtu=None, tx_packets=None, rx_packets=None,
    tx_bytes=None, rx_bytes=None, tx_errors=None, rx_errors=None,
    tx_dropped=None, rx_dropped=None):
    """
    :param agent_id: Agent ID
    :type agent_id: str
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
    :param name: Name of the network interface
    :type name: str
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
    :params tx_dropped: Filters by tx_dropped
    :type tx_dropped: str
    :params rx_dropped: Filters by rx_dropped
    :type rx_dropped: str
    """
    filters = {'adapter': adapter, 'type': type, 'state': state, 'name': name,
               'mtu': mtu, 'tx_packets': tx_packets, 'rx_packets': rx_packets,
               'tx_bytes': tx_bytes, 'rx_bytes': rx_bytes,
               'tx_errors': tx_errors, 'rx_errors': rx_errors,
               'tx_dropped': tx_dropped, 'rx_dropped': rx_dropped}

    f_kwargs = {'agent_id': agent_id, 'offset': offset, 'limit': limit,
                'select': select, 'sort': parse_api_param(sort, 'sort'), 'search': parse_api_param(search, 'search'),
                'filters': filters}

    dapi = DistributedAPI(f=syscollector.get_netiface_agent,
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
def get_network_protocol_info(agent_id, pretty=False, wait_for_complete=False,
    offset=0, limit=None, select=None, sort=None, search=None, iface=None,
    type=None, gateway=None, dhcp=None):
    """
    :param agent_id: Agent ID
    :type agent_id: str
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
    filters = {'iface': iface, 'type': type, 'gateway': gateway, 'dhcp': dhcp}

    f_kwargs = {'agent_id': agent_id, 'offset': offset, 'limit': limit,
                'select': select, 'sort': parse_api_param(sort, 'sort'), 'search': parse_api_param(search, 'search'),
                'filters': filters}

    dapi = DistributedAPI(f=syscollector.get_netproto_agent,
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
def get_os_info(agent_id, pretty=False, wait_for_complete=False,
    select=None):
    """
    :param agent_id: Agent ID
    :type agent_id: str
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    """

    f_kwargs = {'agent_id': agent_id, 'select': select}

    dapi = DistributedAPI(f=syscollector.get_os_agent,
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
def get_packages_info(agent_id, pretty=False, wait_for_complete=False,
    offset=0, limit=None, select=None, sort=None, search=None, vendor=None,
    name=None, architecture=None, format=None, version=None):
    """
    :param agent_id: Agent ID
    :type agent_id: str
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
    :param format: Filters by format
    :type format: str
    :param version: Filters by version
    :type version: str
    """
    filters = {'vendor': vendor, 'name': name, 'architecture': architecture,
               'format': format, 'version': version}

    f_kwargs = {'agent_id': agent_id, 'offset': offset, 'limit': limit,
                'select': select, 'sort': parse_api_param(sort, 'sort'), 'search': parse_api_param(search, 'search'),
                'filters': filters}

    dapi = DistributedAPI(f=syscollector.get_packages_agent,
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
def get_ports_info(agent_id, pretty=False, wait_for_complete=False,
    offset=0, limit=None, select=None, sort=None, search=None, pid=None,
    protocol=None, local_ip=None, local_port=None, remote_ip=None,
    tx_queue=None, state=None):
    """
    :param agent_id: Agent ID
    :type agent_id: str
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
    """
    filters = {'pid': pid, 'protocol': protocol, 'local_ip': local_ip, 'local_port': local_port,
               'remote_ip': remote_ip, 'tx_queue': tx_queue, 'state': state}

    f_kwargs = {'agent_id': agent_id, 'offset': offset, 'limit': limit,
                'select': select, 'sort': parse_api_param(sort, 'sort'), 'search': parse_api_param(search, 'search'),
                'filters': filters}

    dapi = DistributedAPI(f=syscollector.get_ports_agent,
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
def get_processes_info(agent_id, pretty=False, wait_for_complete=False,
    offset=0, limit=None, select=None, sort=None, search=None, pid=None,
    state=None, ppid=None, egroup=None, euser=None, fgroup=None,
    name=None, nlwp=None, pgrp=None, priority=None, rgroup=None,
    ruser=None, sgroup=None, suser=None):
    """
    :param agent_id: Agent ID
    :type agent_id: str
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
    :param pid: Filters by process pid
    :type pid: str
    :param state: Filters by process state
    :type state: str
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
    filters = {'state': state, 'pid': pid,
              'ppid': ppid,'egroup': egroup, 'euser': euser, 'fgroup': fgroup,
              'name': name, 'nlwp': nlwp, 'pgrp': pgrp,
              'priority': priority, 'rgroup': rgroup, 'ruser': ruser,
              'sgroup': sgroup, 'suser': suser}

    f_kwargs = {'agent_id': agent_id, 'offset': offset, 'limit': limit,
                'select': select, 'sort': parse_api_param(sort, 'sort'), 'search': parse_api_param(search, 'search'),
                'filters': filters}

    dapi = DistributedAPI(f=syscollector.get_processes_agent,
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
