# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.syscollector import get_item_agent, _get_agent_items


def get_results_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={},
                      nested=True, array=True, query=''):
    offset = int(offset)
    limit = int(limit)

    valid_select_fields = {'scan_id': 'scan_id', 'scan_time': 'scan_time', 'benchmark': 'benchmark',
                           'profile': 'profile', 'pass': 'pass', 'fail': 'fail', 'error': 'error',
                           'notchecked': 'notchecked', 'unknown': 'unknown', 'score': 'score'}
    table = 'ciscat_results'

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select, search=search, sort=sort,
                          filters=filters, valid_select_fields=valid_select_fields, table=table, nested=nested,
                          array=array, query=query)


def get_ciscat_results(offset=0, limit=common.database_limit, select=None, filters={}, search={}, sort={}, query=''):
    return _get_agent_items(func=get_results_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort, array=True, query=query)
