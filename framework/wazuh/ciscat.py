#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.exception import WazuhException
from wazuh.agent import Agent
from wazuh.utils import plain_dict_to_nested_dict
from operator import itemgetter


def get_item_agent(agent_id, offset, limit, select, search, sort, filters, valid_select_fields, allowed_sort_fields,
                   table, nested=True, array=False):
    Agent(agent_id).get_basic_information()

    if select:
        select_fields = list(set(select['fields']) & set(valid_select_fields))
        if select_fields == []:
            incorrect_fields = map(lambda x: str(x), set(select['fields']) - set(valid_select_fields))
            raise WazuhException(1724, "Allowed select fields: {0}. Fields {1}". \
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


def get_results_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={},
                                nested=True, array=False):
    offset = int(offset)
    limit = int(limit)

    valid_select_fields = {'scan_id', 'scan_time', 'benchmark', 'profile',
                           'pass', 'fail', 'error', 'notchecked', 'unknown', 'score'}
    table = 'ciscat_results'

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                          search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                          valid_select_fields=valid_select_fields, table=table, nested=nested, array=array)


def _get_agent_items(func, offset, limit, select, filters, search, sort, array=False):
    agents, result = Agent.get_agents_overview(select={'fields': ['id']})['items'], []

    limit = int(limit)
    offset = int(offset)
    total = 0

    for agent in agents:
        items = func(agent_id=agent['id'], select=select, filters=filters, limit=limit, offset=offset, search=search,
                     sort=sort, nested=True, array=array)
        if items == {}:
            continue

        total += 1 if not array else items['totalItems']
        items = [items] if not array else items['items']

        for item in items:
            if limit <= len(result):
                break
            item['agent_id'] = agent['id']
            result.append(item)

    if sort and sort['fields']:
        result = sorted(result, key=itemgetter(sort['fields'][0]), reverse=True if sort['order'] == "desc" else False)

    return {'items': result, 'totalItems': total}


def get_ciscat_results(offset=0, limit=common.database_limit, select=None, filters={}, search={}, sort={}):
    return _get_agent_items(func=get_results_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort, array=True)
