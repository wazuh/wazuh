# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

from enum import Enum

from wazuh.core.agent import Agent
from wazuh.core.utils import plain_dict_to_nested_dict, get_fields_to_nest, WazuhDBQuery, WazuhDBBackend


class Type(Enum):
    """Class that enumerates the different types of agent elements."""
    OS = 'os'
    HARDWARE = 'hardware'
    PACKAGES = 'packages'
    PROCESSES = 'processes'
    PORTS = 'ports'
    NETADDR = 'netaddr'
    NETPROTO = 'netproto'
    NETIFACE = 'netiface'
    HOTFIXES = 'hotfixes'
    USERS = 'users'
    GROUPS = 'groups'


def get_valid_fields(element_type: Type, agent_id: str = None) -> dict:
    """Provide a data structure for each element.

    Parameters
    ----------
    element_type : Type
        This is the type of resource we are requesting.
    agent_id : str
        This parameter allows us to know if the agent is Windows or Linux.

    Returns
    -------
    dict
        Valid fields for requested item.
    """
    windows_fields = {'hostname': 'hostname', 'os.version': 'os_version', 'os.name': 'os_name',
                      'architecture': 'architecture', 'os.major': 'os_major', 'os.minor': 'os_minor',
                      'os.build': 'os_build', 'version': 'version', 'scan.time': 'scan_time',
                      'scan.id': 'scan_id', 'os_release': 'os_release', 'os.display_version': 'os_display_version'}
    valid_select_fields = {
        Type.OS: ('sys_osinfo', {'Windows': windows_fields,
                                 'Linux': {
                                     **windows_fields, **{'os.codename': 'os_codename',
                                                          'os.platform': 'os_platform',
                                                          'sysname': 'sysname', 'release': 'release'}}}),
        Type.HARDWARE: ('sys_hwinfo', {'board_serial': 'board_serial', 'cpu.name': 'cpu_name', 'cpu.cores': 'cpu_cores',
                                       'cpu.mhz': 'cpu_mhz', 'ram.total': 'ram_total', 'ram.free': 'ram_free',
                                       'ram.usage': 'ram_usage', 'scan.id': 'scan_id', 'scan.time': 'scan_time'}),
        Type.PACKAGES: ('sys_programs', {'scan.id': 'scan_id', 'scan.time': 'scan_time', 'format': 'format',
                                         'name': 'name', 'priority': 'priority', 'section': 'section', 'size': 'size',
                                         'vendor': 'vendor', 'install_time': 'install_time', 'version': 'version',
                                         'architecture': 'architecture', 'multiarch': 'multiarch', 'source': 'source',
                                         'description': 'description', 'location': 'location'}),
        Type.PROCESSES: ('sys_processes', {'scan.id': 'scan_id', 'scan.time': 'scan_time', 'pid': 'pid', 'name': 'name',
                                           'state': 'state', 'ppid': 'ppid', 'utime': 'utime', 'stime': 'stime',
                                           'cmd': 'cmd', 'argvs': 'argvs', 'euser': 'euser', 'ruser': 'ruser',
                                           'suser': 'suser', 'egroup': 'egroup', 'rgroup': 'rgroup', 'sgroup': 'sgroup',
                                           'fgroup': 'fgroup', 'priority': 'priority', 'nice': 'nice', 'size': 'size',
                                           'vm_size': 'vm_size', 'resident': 'resident', 'share': 'share',
                                           'start_time': 'start_time', 'pgrp': 'pgrp', 'session': 'session',
                                           'nlwp': 'nlwp', 'tgid': 'tgid', 'tty': 'tty', 'processor': 'processor'}),
        Type.PORTS: ('sys_ports', {'scan.id': 'scan_id', 'scan.time': 'scan_time', 'protocol': 'protocol',
                                   'local.port': 'local_port', 'remote.ip': 'remote_ip', 'remote.port': 'remote_port',
                                   'tx_queue': 'tx_queue', 'rx_queue': 'rx_queue', 'inode': 'inode', 'state': 'state',
                                   'pid': 'pid', 'process': 'process', 'local.ip': 'local_ip'}),
        Type.NETADDR: ('sys_netaddr', {'scan.id': 'scan_id', 'iface': 'iface', 'proto': 'proto', 'address': 'address',
                                       'netmask': 'netmask', 'broadcast': 'broadcast'}),
        Type.NETPROTO: ('sys_netproto', {'scan.id': 'scan_id', 'iface': 'iface', 'type': 'type', 'gateway': 'gateway',
                                         'dhcp': 'dhcp'}),
        Type.NETIFACE: ('sys_netiface', {'scan.id': 'scan_id', 'scan.time': 'scan_time', 'name': 'name',
                                         'adapter': 'adapter', 'type': 'type', 'state': 'state', 'mtu': 'mtu',
                                         'mac': 'mac', 'tx.packets': 'tx_packets', 'rx.packets': 'rx_packets',
                                         'tx.bytes': 'tx_bytes', 'rx.bytes': 'rx_bytes', 'tx.errors': 'tx_errors',
                                         'rx.errors': 'rx_errors', 'tx.dropped': 'tx_dropped',
                                         'rx.dropped': 'rx_dropped'}),
        Type.HOTFIXES: ('sys_hotfixes', {'scan_id': 'scan_id', 'scan_time': 'scan_time', 'hotfix': 'hotfix'}),
        Type.USERS: ('sys_users', {'scan.id': 'scan_id', 'scan.time': 'scan_time', 'user.name': 'user_name',
                                   'user.full_name': 'user_full_name', 'user.home': 'user_home', 'user.id': 'user_id',
                                   'user.uid_signed': 'user_uid_signed', 'user.uuid': 'user_uuid',
                                   'user.groups': 'user_groups', 'user.group_id': 'user_group_id', 
                                   'user.group_id_signed': 'user_group_id_signed', 'user.created': 'user_created',
                                   'user.roles': 'user_roles', 'user.shell': 'user_shell', 'user.type': 'user_type',
                                   'user.is_hidden': 'user_is_hidden', 'user.is_remote': 'user_is_remote',
                                   'user.last_login': 'user_last_login',
                                   'user.auth_failed_count': 'user_auth_failed_count',
                                   'user.auth_failed_timestamp': 'user_auth_failed_timestamp',
                                   'user.password_expiration_date': 'user_password_expiration_date',
                                   'user.password_hash_algorithm': 'user_password_hash_algorithm',
                                   'user.password_inactive_days': 'user_password_inactive_days',
                                   'user.password_last_change': 'user_password_last_change',
                                   'user.password_max_days_between_changes': 'user_password_max_days_between_changes',
                                   'user.password_min_days_between_changes': 'user_password_min_days_between_changes',
                                   'user.password_status': 'user_password_status', 
                                   'user.password_warning_days_before_expiration': 'user_password_warning_days_before_expiration',
                                   'process_pid': 'process_pid', 'host_ip': 'host_ip', 'login.status': 'login_status',
                                   'login.tty': 'login_tty', 'login.type': 'login_type', 'checksum': 'checksum'}),
        Type.GROUPS: ('sys_groups', {'scan.id': 'scan_id', 'scan.time': 'scan_time', 'group.id': 'group_id',
                                     'group.name': 'group_name', 'group.description': 'group_description',
                                     'group.id_signed': 'group_id_signed', 'group.uuid': 'group_uuid',
                                     'group.is_hidden': 'group_is_hidden', 'group.users': 'group_users',
                                     'checksum': 'checksum'}),
    }

    if element_type == Type.OS:
        agent_obj = Agent(agent_id)
        agent_obj.get_basic_information()
        valid_select_fields[Type.OS] = list(valid_select_fields[Type.OS])

        # The osinfo fields in database are different in Windows and Linux
        os_name = agent_obj.get_agent_os_name()
        valid_select_fields[Type.OS][1] = valid_select_fields[Type.OS][1]['Windows'] if 'Windows' in os_name else \
            valid_select_fields[Type.OS][1]['Linux']
        valid_select_fields[Type.OS] = tuple(valid_select_fields[Type.OS])

    return valid_select_fields[element_type]


class WazuhDBQuerySyscollector(WazuhDBQuery):
    """Class responsible for obtaining resources from agents."""

    def _filter_status(self, status_filter):
        pass

    nested_fields = ['scan', 'os', 'ram', 'cpu', 'local', 'remote', 'tx', 'rx']

    def __init__(self, array, nested, agent_id, *args, **kwargs):
        super().__init__(backend=WazuhDBBackend(agent_id), default_sort_field='scan_id', get_data=True, count=True,
                         *args, **kwargs)
        self.array = array
        self.nested = nested
        self.date_fields = {'scan.time', 'install_time'}

    def _format_data_into_dictionary(self):
        if self.nested:
            fields_to_nest, non_nested = get_fields_to_nest(self.fields.keys(), self.nested_fields, '.')
            self._data = [plain_dict_to_nested_dict(d, fields_to_nest, non_nested, self.nested_fields, '.') for d in
                          self._data]

        return super()._format_data_into_dictionary() if self.array else next(iter(self._data), {})
