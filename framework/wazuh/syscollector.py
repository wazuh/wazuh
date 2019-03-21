# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.agent import Agent
from wazuh.utils import plain_dict_to_nested_dict, get_fields_to_nest, WazuhDBQuery
from operator import itemgetter


class WazuhDBQuerySyscollector(WazuhDBQuery):

    def __init__(self, array, *args, **kwargs):
        super().__init__(backend='wdb', default_sort_field='scan_id', db_path=None, query='', get_data=True, count=True,
                         *args, **kwargs)
        self.array = array

    def _format_data_into_dictionary(self):
        fields_to_nest, non_nested = get_fields_to_nest(self.fields.keys(), ['scan', 'os'], '_')
        self._data = [plain_dict_to_nested_dict(d, fields_to_nest, non_nested, ['scan', 'os'], '_') for d in self._data]

        return super()._format_data_into_dictionary() if self.array else self._data[0]


def get_item_agent(agent_id, offset, limit, select, search, sort, filters, valid_select_fields,
                   table, array=False):
    db_query = WazuhDBQuerySyscollector(agent_id=agent_id, offset=offset, limit=limit, select=select, search=search,
                                        sort=sort, filters=filters, fields=valid_select_fields, table=table,
                                        array=array)
    return db_query.run()


def get_os_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}):
    """
    Get info about an agent's OS
    """
    agent_obj = Agent(agent_id)
    agent_obj.get_basic_information()

    # The osinfo fields in database are different in Windows and Linux
    os_name = agent_obj.get_agent_attr('os_name')
    windows_fields = {'hostname': 'hostname', 'os_version': 'os_version', 'os_name': 'os_name',
                      'architecture': 'architecture', 'os_major': 'os_major', 'os_minor': 'os_minor',
                      'os_build': 'os_build', 'version': 'version', 'scan_time': 'scan_time',
                      'scan_id': 'scan_id'}
    linux_fields = {**windows_fields, **{'os_codename': 'os_codename', 'os_platform': 'os_platform',
                                         'sysname': 'sysname', 'release': 'release'}}

    valid_select_fields = windows_fields if 'Windows' in os_name else linux_fields

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                         search=search, sort=sort, filters=filters, valid_select_fields=valid_select_fields,
                          table='sys_osinfo')


def get_hardware_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}):
    """
    Get info about an agent's OS
    """
    valid_select_fields = {'board_serial': 'board_serial', 'cpu_name': 'cpu_name', 'cpu_cores': 'cpu_cores',
                           'cpu_mhz': 'cpu_mhz', 'ram_total': 'ram_total', 'ram_free': 'ram_free',
                           'ram_usage': 'ram_usage', 'scan_id': 'scan_id', 'scan_time': 'scan_time'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                         search=search, sort=sort, filters=filters, valid_select_fields=valid_select_fields,
                          table='sys_hwinfo')


def get_packages_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}):
    """
    Get info about an agent's programs
    """
    valid_select_fields = {'scan_id': 'scan_id', 'scan_time': 'scan_time', 'format': 'format', 'name': 'name',
                           'priority': 'priority', 'section': 'section', 'size': 'size', 'vendor': 'vendor',
                           'install_time': 'install_time', 'version': 'version', 'architecture': 'architecture',
                           'multiarch': 'multiarch', 'source': 'source', 'description': 'description',
                           'location': 'location'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                          search=search, sort=sort, filters=filters, valid_select_fields=valid_select_fields,
                          table='sys_programs', array=True)


def get_processes_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}):
    """
    Get info about an agent's processes
    """
    valid_select_fields = {'scan_id': 'scan_id', 'scan_time': 'scan_time', 'pid': 'pid', 'name': 'name',
                           'state': 'state', 'ppid': 'ppid', 'utime': 'utime', 'stime': 'stime', 'cmd': 'cmd',
                           'argvs': 'argvs', 'euser': 'euser', 'ruser': 'ruser', 'suser': 'suser',
                           'egroup': 'egroup', 'rgroup': 'rgroup', 'sgroup': 'sgroup', 'fgroup': 'fgroup',
                           'priority': 'priority', 'nice': 'nice', 'size': 'size', 'vm_size': 'vm_size',
                           'resident': 'resident', 'share': 'share', 'start_time': 'start_time', 'pgrp': 'pgrp',
                           'session': 'session', 'nlwp': 'nlwp', 'tgid': 'tgid', 'tty': 'tty', 'processor': 'processor'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                          search=search, sort=sort, filters=filters, valid_select_fields=valid_select_fields,
                          table='sys_processes', array=True)


def get_ports_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}):
    """
    Get info about an agent's ports
    """
    valid_select_fields = {'scan_id': 'scan_id', 'scan_time': 'scan_time', 'protocol': 'protocol',
                           'local_port': 'local_port', 'remote_ip': 'remote_ip', 'remote_port': 'remote_port',
                           'tx_queue': 'tx_queue', 'rx_queue': 'rx_queue', 'inode': 'inode', 'state': 'state',
                           'pid': 'pid', 'process': 'process', 'local_ip': 'local_ip'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select, search=search, sort=sort,
                          filters=filters, valid_select_fields=valid_select_fields, table='sys_ports', array=True)


def get_netaddr_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}):
    """
    Get info about an agent's network address
    """
    valid_select_fields = {'scan_id': 'scan_id', 'iface': 'iface', 'proto': 'proto', 'address': 'address',
                           'netmask': 'netmask', 'broadcast': 'broadcast'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select, search=search, sort=sort,
                          filters=filters, valid_select_fields=valid_select_fields, table='sys_netaddr', array=True)


def get_netproto_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}):
    """
    Get info about an agent's network protocol
    """
    valid_select_fields = {'scan_id': 'scan_id', 'iface': 'iface', 'type': 'type', 'gateway': 'gateway', 'dhcp': 'dhcp'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select, search=search, sort=sort,
                          filters=filters, valid_select_fields=valid_select_fields, table='sys_netproto', array=True)


def get_netiface_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}):
    """
    Get info about an agent's network interface
    """
    valid_select_fields = {'scan_id': 'scan_id', 'scan_time': 'scan_time', 'name': 'name', 'adapter': 'adapter',
                           'type': 'type', 'state': 'state', 'mtu': 'mtu', 'mac': 'mac', 'tx_packets': 'tx_packets',
                           'rx_packets': 'rx_packets', 'tx_bytes': 'tx_bytes', 'rx_bytes': 'rx_bytes',
                           'tx_errors': 'tx_errors', 'rx_errors': 'rx_errors', 'tx_dropped': 'tx_dropped',
                           'rx_dropped': 'rx_dropped'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select, search=search, sort=sort,
                          filters=filters, valid_select_fields=valid_select_fields, table='sys_netiface', array=True)


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
