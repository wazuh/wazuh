# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from operator import itemgetter

from wazuh import common
from wazuh.core.core_agent import Agent
from wazuh.core.syscollector import WazuhDBQuerySyscollector, get_fields_to_nest, get_valid_fields, Type
from wazuh.rbac.decorators import expose_resources
from wazuh.utils import plain_dict_to_nested_dict
from wazuh.results import AffectedItemsWazuhResult


@expose_resources(actions=['syscollector:read'], resources=['agent:id:{agent_id}'])
def get_item_agent(agent_id, offset=0, limit=common.database_limit, select=None, search=None, sort=None, filters=None,
                   query='', array=True, nested=True, element_type='os'):
    """
    Get info about an agent
    """
    result = AffectedItemsWazuhResult(none_msg='No items was shown',
                                      some_msg='Some items could not be shown',
                                      all_msg='All specified items were shown')
    table, valid_select_fields = get_valid_fields(Type(element_type), agent_id[0])
    db_query = WazuhDBQuerySyscollector(agent_id=agent_id[0], offset=offset, limit=limit, select=select, search=search,
                                        sort=sort, filters=filters, fields=valid_select_fields, table=table,
                                        array=array, nested=nested, query=query).run()
    result.affected_items = db_query['items']
    result.total_affected_items = db_query['totalItems']

    return result


def _get_agent_items(func, offset, limit, select, filters, search, sort, array=False, query=''):
    agents, result = Agent.get_agents_overview(select=['id'])['items'], []
    total = 0

    for agent in agents:
        items = func(agent_id=agent['id'], select=select, filters=filters, limit=limit, offset=offset, search=search,
                     sort=sort, nested=False, q=query)
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
            result = sorted(result, key=itemgetter(sort['fields'][0]),
                            reverse=True if sort['order'] == "desc" else False)

        fields_to_nest, non_nested = get_fields_to_nest(result[0].keys(), '.')
    else:
        fields_to_nest, non_nested = None, None

    return {
        'items': list(
            map(lambda x: plain_dict_to_nested_dict(x, fields_to_nest, non_nested, WazuhDBQuerySyscollector.nested_fields, '.'), result)
        ), 'totalItems': total}
