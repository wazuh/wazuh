# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core import common
from wazuh.core.agent import get_agents_info
from wazuh.core.exception import WazuhError, WazuhResourceNotFound
from wazuh.core.results import AffectedItemsWazuhResult, merge
from wazuh.core.syscollector import WazuhDBQuerySyscollector
from wazuh.rbac.decorators import expose_resources


@expose_resources(actions=["ciscat:read"], resources=["agent:id:{agent_list}"])
def get_ciscat_results(agent_list=None, offset=0, limit=common.database_limit, select=None, search=None, sort=None,
                       filters=None, nested=True, array=True, q=''):
    """ Get CIS-CAT results for a list of agents

    :param agent_list: list of Agent ID to get scan results from. Currently, only first item will be considered
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return
    :param search: Looks for items with the specified string. Begins with '-' for a complementary search
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    :param filters: Fields to filter by
    :param nested: Nested fields
    :param array: Array
    :param q: Defines query to filter in DB.
    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(
        all_msg='All CISCAT results were returned',
        some_msg='Some CISCAT results were not returned',
        none_msg='No CISCAT results were returned',
        sort_fields=['agent_id'] if sort is None else sort['fields'],
        sort_casting=['str'],
        sort_ascending=[sort['order'] == 'asc' for _ in sort['fields']] if sort is not None else ['True']
    )

    valid_select_fields = {'scan.id': 'scan_id', 'scan.time': 'scan_time', 'benchmark': 'benchmark',
                           'profile': 'profile', 'pass': 'pass', 'fail': 'fail', 'error': 'error',
                           'notchecked': 'notchecked', 'unknown': 'unknown', 'score': 'score'}
    table = 'ciscat_results'

    for agent in agent_list:
        try:
            if agent not in get_agents_info():
                raise WazuhResourceNotFound(1701)
            db_query = WazuhDBQuerySyscollector(agent_id=agent, offset=offset, limit=limit, select=select,
                                                search=search,
                                                sort=sort, filters=filters, fields=valid_select_fields, table=table,
                                                array=array, nested=nested, query=q)
            data = db_query.run()

            if len(data['items']) > 0:
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
