#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.exception import WazuhException
from wazuh.agent import Agent
from wazuh import Wazuh
from wazuh.utils import plain_dict_to_nested_dict, cut_array, sort_array, search_array
from operator import itemgetter

def get_item_agent(agent_id, offset, limit, select, search, sort, filters, valid_select_fields, allowed_sort_fields, table, nested=True, array=False):
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
        return_data = response
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
    offset = int(offset)
    limit = int(limit)

    # The osinfo fields in database are different in Windows and Linux
    os_name = agent_obj.get_agent_attr('os_name')
    windows_fields = {'hostname', 'os_version', 'os_name', 'architecture',
                      'scan_time', 'scan_id'}
    linux_fields   = windows_fields | {'sysname', 'version', 'release'}

    valid_select_fields = windows_fields if 'Windows' in os_name else linux_fields

    allowed_sort_fields = {'sysname', 'os_name', 'hostname',
                           'version', 'architecture','release', 'os_version'}
                           
    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select, 
                         search=search, sort=sort, filters=filters, allowed_sort_fields=allowed_sort_fields,
                         valid_select_fields=valid_select_fields, table='sys_osinfo', nested=nested)


def get_hardware_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=True):
    """
    Get info about an agent's OS
    """
    offset = int(offset)
    limit = int(limit)
    
    valid_select_fields = {'board_serial', 'cpu_name', 'cpu_cores', 'cpu_mhz',
                           'ram_total', 'ram_free', 'scan_id', 'scan_time'}
              
    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select, 
                         search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                         valid_select_fields=valid_select_fields, table='sys_hwinfo', nested=nested)


def get_packages_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={}, nested=False):
    """
    Get info about an agent's programs
    """
    offset = int(offset)
    limit = int(limit)
    valid_select_fields = {'scan_id', 'scan_time', 'format', 'name',
                           'vendor', 'version', 'architecture', 'description'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select, 
                         search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                         valid_select_fields=valid_select_fields, table='sys_programs', array=True, nested=nested)


def _get_agent_items(func, offset, limit, select, filters, search, sort, array=False):
    agents, result = Agent.get_agents_overview(select={'fields':['id']})['items'], []

    limit = int(limit)
    offset = int(offset)
    found_limit = False

    for agent in agents:
        items = func(agent_id = agent['id'], select = select, filters = filters, limit = limit, offset = offset, search = search, sort=sort, nested=False)
        if items == {}:
            continue

        items = [items] if not array else items['items']

        for item in items:
            item['agent_id'] = agent['id']
            result.append(item)
            if limit <= len(result):
                found_limit = True
                break;
        if found_limit:
            break

    if sort and sort['fields']:
        result = sorted(result, key=itemgetter(sort['fields'][0]), reverse=True if sort['order'] == "desc" else False)

    return {'items': result, 'totalItems': len(result)}


def get_packages(offset=0, limit=common.database_limit, select=None, filters={}, search={}, sort={}):
    return _get_agent_items(func=get_packages_agent, offset=offset, limit=limit, select=select, 
                            filters=filters, search=search, sort=sort, array=True)


def get_os(filters={}, offset=0, limit=common.database_limit, select={}, search={}, sort={}):
    return _get_agent_items(func=get_os_agent, offset=offset, limit=limit, select=select, 
                            filters=filters, search=search, sort=sort)


def get_hardware(offset=0, limit=common.database_limit, select=None, sort=None, filters={}, search={}):
    return _get_agent_items(func=get_hardware_agent, offset=offset, limit=limit, select=select, 
                            filters=filters, search=search, sort=sort)
