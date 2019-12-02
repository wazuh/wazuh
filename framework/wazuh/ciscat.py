# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.core.core_utils import get_agents_info
from wazuh.core.syscollector import WazuhDBQuerySyscollector
from wazuh.exception import WazuhError
from wazuh.rbac.decorators import expose_resources
from wazuh.results import AffectedItemsWazuhResult


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
    result = AffectedItemsWazuhResult(all_msg='All CISCAT results loaded',
                                      some_msg='Some CISCAT results were not loaded',
                                      none_msg='No CISCAT results were loaded')
    valid_select_fields = {'scan.id': 'scan_id', 'scan.time': 'scan_time', 'benchmark': 'benchmark',
                           'profile': 'profile', 'pass': 'pass', 'fail': 'fail', 'error': 'error',
                           'notchecked': 'notchecked', 'unknown': 'unknown', 'score': 'score'}
    table = 'ciscat_results'

    for agent in agent_list:
        try:
            if agent not in get_agents_info():
                raise WazuhError(1701)
            db_query = WazuhDBQuerySyscollector(agent_id=agent, offset=offset, limit=limit, select=select, search=search,
                                                sort=sort, filters=filters, fields=valid_select_fields, table=table,
                                                array=array, nested=nested, query=q)
            data = db_query.run()
            result.affected_items.append(data['items'])
            result.total_affected_items = data['totalItems']
        except WazuhError as e:
            result.add_failed_item(id_=agent, error=e)

    return result


def get_ciscat_experimental(offset=0, limit=common.database_limit, select=None, filters={}, search={}, sort=None, q=''):
    return _get_agent_items(func=get_ciscat_results, offset=offset, limit=limit, select=select, filters=filters,
                            search=search, sort=sort, array=True, query=q)
