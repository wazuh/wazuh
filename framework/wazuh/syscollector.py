#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.exception import WazuhException
from wazuh.agent import Agent
from wazuh import Wazuh
from wazuh.utils import plain_dict_to_nested_dict, cut_array, sort_array, search_array

def get_os_agent(agent_id, select=None):
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

    try:
    	return plain_dict_to_nested_dict(agent_obj._load_info_from_agent_db(table='sys_osinfo', select=select_fields)[0])
    except IndexError as e:
    	# there's no data to return
    	return {}


def get_hardware_agent(agent_id, select=None):
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

    try:
    	return plain_dict_to_nested_dict(Agent(agent_id)._load_info_from_agent_db(table='sys_hwinfo', select=select_fields)[0])
    except IndexError as e:
    	return {}


def get_packages_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}):
    """
    Get info about an agent's programs
    """
    valid_select_fields = {'scan_id', 'scan_time', 'format', 'name',
                           'vendor', 'version', 'architecture', 'description'}
    allowed_sort_fields = {'scan_id', 'scan_time', 'format', 'name',
                           'vendor', 'version', 'architecture', 'description'}

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

    # Sorting
    if sort and sort['fields']:
        # Check if every element in sort['fields'] is in allowed_sort_fields.
        if not set(sort['fields']).issubset(allowed_sort_fields):
            raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(allowed_sort_fields, sort['fields']))

    response, total = Agent(agent_id)._load_info_from_agent_db(table='sys_programs',
                                offset=offset, limit=limit, select=select_fields,
                                count=True, sort=sort, search=search, filters=filters)

    return {'totalItems':total, 'items':response}


def get_packages(offset=0, limit=common.database_limit, select=None, filters={}):

    agents, result = Agent.get_agents_overview(select={'fields':['id']})['items'], []

    for agent in agents:
        agent_packages = get_packages_agent(agent_id = agent['id'], select = select,
                                filters = filters, limit = limit, offset = offset)

        items = agent_packages['items']
        for item in items:
            item['agent_id'] = agent['id']
            result.append(item)

    return {'items': result, 'totalItems': len(result)}


def get_os(offset=0, limit=common.database_limit, select=None, sort=None, filters={}, search={}):
    valid_select_fields = {'scan_id', 'scan_time', 'format', 'name',
                           'vendor', 'version', 'architecture', 'description'}
    allowed_sort_fields = {'scan_id', 'scan_time', 'format', 'name',
                           'vendor', 'version', 'architecture', 'description'}

    agents = Agent.get_agents_overview(select={'fields':['id']})['items']
    result = []
    for agent in agents:
        agent_programs = get_os_agent(agent_id=agent['id'], select=select)
        if agent_programs and len(agent_programs) > 0:
            result.append(agent['id'])

    if search:
        result = search_array(result, search['value'], search['negation'])

    if sort:
        result = sort_array(result, sort['fields'], sort['order'])

    return {'items': cut_array(result, offset, limit), 'totalItems': len(result)}


def get_hardware(offset=0, limit=common.database_limit, select=None, sort=None, filters={}, search={}):
    valid_select_fields = {'scan_id', 'scan_time', 'format', 'name',
                           'vendor', 'version', 'architecture', 'description'}
    allowed_sort_fields = {'scan_id', 'scan_time', 'format', 'name',
                           'vendor', 'version', 'architecture', 'description'}

    agents = Agent.get_agents_overview(select={'fields':['id']})['items']
    result = []
    for agent in agents:
        agent_programs = get_os_agent(agent_id=agent['id'], select=select)
        if agent_programs and len(agent_programs) > 0:
            result.append(agent['id'])

    if search:
        result = search_array(result, search['value'], search['negation'])

    if sort:
        result = sort_array(result, sort['fields'], sort['order'])

    return {'items': cut_array(result, offset, limit), 'totalItems': len(result)}
