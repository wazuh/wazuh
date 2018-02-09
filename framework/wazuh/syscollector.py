#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.exception import WazuhException
from wazuh.agent import Agent
from wazuh import Wazuh
from wazuh.utils import plain_dict_to_nested_dict

def get_os(agent_id, select={}, search={}):
    """
    Get info about an agent's OS
    """
    # The osinfo fields in database are different in Windows and Linux
    agent_obj = Agent(agent_id)

    os_name = agent_obj.get_agent_attr('os_name')
    windows_fields = ['os_name', 'os_major', 'os_minor', 'os_build',
                      'os_version', 'nodename', 'machine']
    linux_fields   = ['architecture', 'hostname', 'os_name', 'os_version',
    				  'release', 'scan_id', 'scan_time', 'sysname',
    				  'version']

    valid_select_fields = windows_fields if 'Windows' in os_name else linux_fields

    if select:
        select_fields = list(set(select['fields']) & set(windows_fields)) \
                        if 'Windows' in os_name else \
                        list(set(select['fields']) & set(linux_fields))
        if select_fields == []:
            uncorrect_fields = map(lambda x: str(x), set(select['fields']) - set(valid_select_fields))
            raise WazuhException(1724, "Allowed select fields: {0}. Fields {1}".\
                format(', '.join(valid_select_fields), ','.join(uncorrect_fields)))
    else:
        select_fields = valid_select_fields

    if search:
    	search['fields'] = select_fields

    try:
    	return plain_dict_to_nested_dict(agent_obj._load_info_from_agent_db(table='sys_osinfo', select=select_fields, search=search)[0])
    except IndexError as e:
    	# there's no data to return
    	return {}


def get_hardware(agent_id, select={}, search={}):
    """
    Get info about an agent's OS
    """
    valid_select_fields = ['board_serial', 'cpu_name', 'cpu_cores', 'cpu_mhz',
                           'ram_total', 'ram_free', 'scan_id', 'scan_time']

    if select:
        if not set(select['fields']).issubset(valid_select_fields):
            uncorrect_fields = map(lambda x: str(x), set(select['fields']) - set(valid_select_fields))
            raise WazuhException(1724, "Allowed select fields: {0}. Fields {1}".\
                    format(', '.join(valid_select_fields), ','.join(uncorrect_fields)))
        select_fields = select['fields']
    else:
        select_fields = valid_select_fields

    if search:
    	search['fields'] = select_fields

    try:
    	return plain_dict_to_nested_dict(Agent(agent_id)._load_info_from_agent_db(table='sys_hwinfo', select=select_fields, search=search)[0])
    except IndexError as e:
    	return {}


def get_programs(agent_id, offset=0, limit=common.database_limit, select={}, search={}):
    """
    Get info about an agent's programs
    """
    valid_select_fields = ['scan_id', 'scan_time', 'format', 'name',
                           'vendor', 'version', 'architecture', 'description']

    if select:
        if not set(select['fields']).issubset(valid_select_fields):
            uncorrect_fields = map(lambda x: str(x), set(select['fields']) - set(valid_select_fields))
            raise WazuhException(1724, "Allowed select fields: {0}. Fields {1}".\
                    format(', '.join(valid_select_fields), ','.join(uncorrect_fields)))
        select_fields = select['fields']
    else:
        select_fields = valid_select_fields

    if search:
    	search['fields'] = select_fields

    response, total = Agent(agent_id)._load_info_from_agent_db(table='sys_programs', select=select_fields, count=True, search=search)
    return {'totalItems':total, 'items':response}
