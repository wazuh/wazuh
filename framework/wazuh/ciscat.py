# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core import common
from wazuh.core.agent import get_agents_info
from wazuh.core.exception import WazuhResourceNotFound
from wazuh.core.results import AffectedItemsWazuhResult, merge
from wazuh.core.syscollector import WazuhDBQuerySyscollector
from wazuh.rbac.decorators import expose_resources


@expose_resources(actions=["ciscat:read"], resources=["agent:id:{agent_list}"])
def get_ciscat_results(agent_list: list = None, offset: int = 0, limit: int = common.DATABASE_LIMIT,
                       select: list = None, search: str = None, sort: dict = None, filters: dict = None,
                       nested: bool = True, array: bool = True, q: str = '') -> AffectedItemsWazuhResult:
    """Get CIS-CAT results for a list of agents

    Parameters
    ----------
    agent_list : list
        List of Agent ID to get scan results from. Currently, only first item will be considered.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : list
        Select which fields to return.
    search : str
        Looks for items with the specified string. Begins with '-' for a complementary search.
    sort : dict
        Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    filters : dict
        Fields to filter by.
    nested : bool
        Nested fields.
    array : bool
        Array.
    q : str
        Defines query to filter in DB.

    Returns
    -------
    AffectedItemsWazuhResult
        Paths of all CDB lists.
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

    system_agents = get_agents_info()
    for agent in agent_list:
        try:
            if agent not in system_agents:
                raise WazuhResourceNotFound(1701)
            with WazuhDBQuerySyscollector(agent_id=agent, offset=offset, limit=limit, select=select,
                                          search=search,
                                          sort=sort, filters=filters, fields=valid_select_fields, table=table,
                                          array=array, nested=nested, query=q) as db_query:
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
