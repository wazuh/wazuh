# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core import common
from wazuh.core.agent import get_agents_info
from wazuh.core.exception import WazuhError, WazuhResourceNotFound
from wazuh.core.results import AffectedItemsWazuhResult, merge
from wazuh.core.syscollector import WazuhDBQuerySyscollector, get_valid_fields, Type
from wazuh.rbac.decorators import expose_resources


@expose_resources(actions=['syscollector:read'], resources=['agent:id:{agent_list}'])
def get_item_agent(agent_list, offset=0, limit=common.database_limit, select=None, search=None, sort=None, filters=None,
                   q='', array=True, nested=True, element_type='os'):
    """ Get syscollector information about a list of agents.

    :param agent_list: List of agents ID's.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
    :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
    :param q: Defines query to filter in DB.
    :param filters: Fields to filter by
    :param nested: Nested fields
    :param array: Array
    :param element_type: Type of element to get syscollector information from
    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(
        none_msg='No syscollector information was returned',
        some_msg='Some syscollector information was not returned',
        all_msg='All specified syscollector information was returned',
        sort_fields=['agent_id'] if sort is None else sort['fields'],
        sort_casting=['str'],
        sort_ascending=[sort['order'] == 'asc' for _ in sort['fields']] if sort is not None else ['True']
    )

    for agent in agent_list:
        try:
            if agent not in get_agents_info():
                raise WazuhResourceNotFound(1701)
            table, valid_select_fields = get_valid_fields(Type(element_type), agent_id=agent)
            db_query = WazuhDBQuerySyscollector(agent_id=agent, offset=offset, limit=limit, select=select,
                                                search=search,
                                                sort=sort, filters=filters, fields=valid_select_fields, table=table,
                                                array=array, nested=nested, query=q)
            data = db_query.run()
            for item in data['items']:
                item['agent_id'] = agent
                result.affected_items.append(item)
            result.total_affected_items += data['totalItems']
        except WazuhResourceNotFound as e:
            result.add_failed_item(id_=agent, error=e)

    result.affected_items = merge(*[[res] for res in result.affected_items],
                                  criteria=result.sort_fields,
                                  ascending=result.sort_ascending,
                                  types=result.sort_casting)

    return result
