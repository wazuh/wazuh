# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.syscollector import get_item_agent


def get_ciscat_results(agent_id=None, offset=0, limit=common.database_limit, select=None, search=None, sort=None,
                       filters=None, q=''):
    """ Get CIS-CAT results from an agent

    :param agent_id: Agent ID to get scan results from
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return
    :param search: Looks for items with the specified string. Begins with '-' for a complementary search
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    :param filters: Fields to filter by
    :param q: Defines query to filter in DB.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    valid_select_fields = {'scan.id': 'scan_id', 'scan.time': 'scan_time', 'benchmark': 'benchmark',
                           'profile': 'profile', 'pass': 'pass', 'fail': 'fail', 'error': 'error',
                           'notchecked': 'notchecked', 'unknown': 'unknown', 'score': 'score'}
    table = 'ciscat_results'

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select, search=search, sort=sort,
                          filters=filters, valid_select_fields=valid_select_fields,
                          table=table, nested=True, array=True, query=q)
