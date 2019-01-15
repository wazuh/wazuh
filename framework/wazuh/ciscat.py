#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.syscollector import get_item_agent, _get_agent_items


def get_results_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={},
                                nested=True, array=True):
    offset = int(offset)
    limit = int(limit)

    valid_select_fields = {'scan_id', 'scan_time', 'benchmark', 'profile',
                           'pass', 'fail', 'error', 'notchecked', 'unknown', 'score'}
    table = 'ciscat_results'

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                          search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                          valid_select_fields=valid_select_fields, table=table, nested=nested, array=array)


def get_ciscat_results(offset=0, limit=common.database_limit, select=None, filters={}, search={}, sort={}):
    return _get_agent_items(func=get_results_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort, array=True)
