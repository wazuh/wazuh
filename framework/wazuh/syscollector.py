#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.exception import WazuhException
from wazuh.agent import Agent
from wazuh.utils import plain_dict_to_nested_dict, get_fields_to_nest
from operator import itemgetter


def get_item_agent(agent_id, offset, limit, select, search, sort, filters, valid_select_fields, allowed_sort_fields, table, nested=True, array=False):
    Agent(agent_id).get_basic_information()

    if select:
        select_fields = list(set(select['fields']) & set(valid_select_fields))
        if select_fields == []:
            incorrect_fields = map(lambda x: str(x), set(select['fields']) - set(valid_select_fields))
            raise WazuhException(1724, "Allowed select fields: {0}. Fields {1}".\
                format(', '.join(valid_select_fields), ','.join(incorrect_fields)))
    else:
        select_fields = valid_select_fields

    if search:
        search['fields'] = valid_select_fields

    # Sorting
    if sort and sort['fields']:
        # Check if every element in sort['fields'] is in allowed_sort_fields.
        if not set(sort['fields']).issubset(allowed_sort_fields):
            raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(
                        ', '.join(allowed_sort_fields), ','.join(sort['fields'])))

    response, total = Agent(agent_id)._load_info_from_agent_db(table=table,
                                                               offset=offset, limit=limit, select=select_fields,
                                                               count=True, sort=sort, search=search, filters=filters)

    if array:
        return_data = response if not nested else list(map(lambda x: plain_dict_to_nested_dict(x), response))
    elif not response:
        return_data = {}
    else:
        return_data = response[0] if not nested else plain_dict_to_nested_dict(response[0])

    return {'items': return_data, 'totalItems': total} if array else return_data


def get_os_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about an agent's OS
    """
    agent_obj = Agent(agent_id)
    agent_obj.get_basic_information()

    # The osinfo fields in database are different in Windows and Linux
    os_name = agent_obj.get_agent_attr('os_name')
    windows_fields = {'hostname', 'os_version', 'os_name',
                      'architecture', 'os_major', 'os_minor', 'os_build',
                      'version', 'scan_time', 'scan_id'}
    linux_fields   = windows_fields | {'os_codename', 'os_platform', 'sysname', 'release'}

    valid_select_fields = windows_fields if 'Windows' in os_name else linux_fields

    allowed_sort_fields = {'os_name', 'hostname', 'architecture'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                         search=search, sort=sort, filters=filters, allowed_sort_fields=allowed_sort_fields,
                         valid_select_fields=valid_select_fields, table='sys_osinfo', nested=nested)


def get_hardware_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about an agent's OS
    """
    valid_select_fields = {'board_serial', 'cpu_name', 'cpu_cores', 'cpu_mhz',
                           'ram_total', 'ram_free', 'ram_usage', 'scan_id', 'scan_time'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                         search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                         valid_select_fields=valid_select_fields, table='sys_hwinfo', nested=nested)


def get_packages_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about an agent's programs
    """
    valid_select_fields = {'scan_id', 'scan_time', 'format', 'name', 'priority',
                           'section', 'size', 'vendor', 'install_time', 'version',
                           'architecture', 'multiarch', 'source', 'description',
                           'location'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                         search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                         valid_select_fields=valid_select_fields, table='sys_programs', array=True, nested=nested)


def get_processes_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about an agent's processes
    """
    valid_select_fields = {'scan_id', 'scan_time', 'pid', 'name',
                           'state', 'ppid', 'utime', 'stime', 'cmd', 'argvs',
                           'euser', 'ruser', 'suser', 'egroup', 'rgroup',
                           'sgroup', 'fgroup', 'priority', 'nice', 'size',
                           'vm_size', 'resident', 'share', 'start_time', 'pgrp',
                           'session', 'nlwp', 'tgid', 'tty', 'processor'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                         search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                         valid_select_fields=valid_select_fields, table='sys_processes', array=True, nested=nested)


def get_ports_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about an agent's ports
    """
    valid_select_fields = {'scan_id', 'scan_time', 'protocol', 'local_ip',
                           'local_port', 'remote_ip', 'remote_port', 'tx_queue', 'rx_queue', 'inode',
                           'state', 'pid', 'process'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                         search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                         valid_select_fields=valid_select_fields, table='sys_ports', array=True, nested=nested)


def get_netaddr_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about an agent's network address
    """
    valid_select_fields = {'scan_id', 'iface', 'proto', 'address',
                           'netmask', 'broadcast'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                         search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                         valid_select_fields=valid_select_fields, table='sys_netaddr', array=True, nested=nested)


def get_netproto_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about an agent's network protocol
    """
    valid_select_fields = {'scan_id', 'iface', 'type',
                           'gateway', 'dhcp'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                         search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                         valid_select_fields=valid_select_fields, table='sys_netproto', array=True, nested=nested)


def get_netiface_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about an agent's network interface
    """
    valid_select_fields = {'scan_id', 'scan_time', 'name',
                           'adapter', 'type', 'state', 'mtu', 'mac', 'tx_packets',
                            'rx_packets', 'tx_bytes', 'rx_bytes', 'tx_errors', 'rx_errors',
                           'tx_dropped', 'rx_dropped'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                         search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                         valid_select_fields=valid_select_fields, table='sys_netiface', array=True, nested=nested)


def _get_agent_items(func, offset, limit, select, filters, search, sort, array=False):
    agents, result = Agent.get_agents_overview(select={'fields': ['id']})['items'], []

    total = 0

    for agent in agents:
        items = func(agent_id = agent['id'], select = select, filters = filters, limit = limit, offset = offset, search = search, sort=sort, nested=False)
        if items == {}:
            continue

        total += 1 if not array else items['totalItems']
        items = [items] if not array else items['items']

        for item in items:
            if 0 < limit <= len(result):
                break
            item['agent_id'] = agent['id']
            result.append(item)

    if result:
        if sort and sort['fields']:
            result = sorted(result, key=itemgetter(sort['fields'][0]), reverse=True if sort['order'] == "desc" else False)

        fields_to_nest, non_nested = get_fields_to_nest(result[0].keys(), '_')
    return {'items': list(map(lambda x: plain_dict_to_nested_dict(x, fields_to_nest, non_nested), result)), 'totalItems': total}


def get_packages(offset=0, limit=common.database_limit, select=None, filters={}, search={}, sort={}):
    return _get_agent_items(func=get_packages_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort, array=True)


def get_os(filters={}, offset=0, limit=common.database_limit, select={}, search={}, sort={}):
    return _get_agent_items(func=get_os_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort)


def get_hardware(offset=0, limit=common.database_limit, select=None, sort=None, filters={}, search={}):
    return _get_agent_items(func=get_hardware_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort)


def get_processes(offset=0, limit=common.database_limit, select=None, sort=None, filters={}, search={}):
    return _get_agent_items(func=get_processes_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort, array=True)


def get_ports(offset=0, limit=common.database_limit, select=None, sort=None, filters={}, search={}):
    return _get_agent_items(func=get_ports_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort, array=True)


def get_netaddr(offset=0, limit=common.database_limit, select=None, sort=None, filters={}, search={}):
    return _get_agent_items(func=get_netaddr_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort, array=True)


def get_netproto(offset=0, limit=common.database_limit, select=None, sort=None, filters={}, search={}):
    return _get_agent_items(func=get_netproto_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort, array=True)


def get_netiface(offset=0, limit=common.database_limit, select=None, sort=None, filters={}, search={}):
    return _get_agent_items(func=get_netiface_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort, array=True)
