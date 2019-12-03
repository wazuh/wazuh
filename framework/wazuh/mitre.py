#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Framework module for getting information from Wazuh MITRE database."""

import json
from typing import Dict, Optional

from wazuh.utils import WazuhDBBackend, WazuhDBQuery

mitre_fields = {'id': 'id',
                'json': 'json',
                'phase_name': 'phase_name',
                'platform_name': 'platform_name'}

select_fields = "id, json"

from_fields = "attack LEFT JOIN has_phase ON attack.id = has_phase.attack_id" \
              " LEFT JOIN has_platform ON attack.id = has_platform.attack_id"

group_by_fields = "GROUP BY id"

count_fields = "COUNT(DISTINCT id)"

default_query = f"SELECT {select_fields} FROM {from_fields} {group_by_fields}"


class WazuhDBQueryMitre(WazuhDBQuery):
    """Create a WazuhDB query for getting data from Mitre database."""

    def __init__(self, offset: int = 0, limit: int = 10, query: str = '',
                 count: bool = True, get_data: bool = True,
                 table: str = 'attack', sort: Optional[Dict] = None,
                 default_query: str = default_query,
                 default_sort_field: str = 'id', fields: Dict = mitre_fields,
                 count_field: str = 'id', search: str = ''):
        """Create an instance of WazuhDBQueryMitre query."""
        self.default_query = default_query
        self.count_field = count_field

        WazuhDBQuery.__init__(self, offset=offset, limit=limit,
                              table=table, sort=sort, search=search,
                              select=None, fields=fields,
                              default_sort_field=default_sort_field,
                              default_sort_order='ASC', filters=None,
                              query=query, count=count, get_data=get_data,
                              backend=WazuhDBBackend(query_format='mitre'))

    def _default_query(self) -> str:
        return self.default_query

    def _get_total_items(self):
        final_query = self.query.replace(group_by_fields, '')
        final_query = final_query.replace(select_fields, count_fields)
        self.total_items = self.backend.execute(final_query, self.request)

    def _execute_data_query(self):
        if 'GROUP BY' in self.query:
            final_query = self.query.replace(group_by_fields, '')
            pos_order_by = final_query.find('ORDER BY')
            final_query = final_query[0:pos_order_by] + f' {group_by_fields} '\
                + final_query[pos_order_by:]
        self._data = self.backend.execute(final_query, self.request)


def get_attack(attack: str = '', phase: str = '', platform: str = '', 
               search: str = '', offset: int = 0, limit: int = 10, 
               sort: Optional[Dict] = None, q: str = '') -> Dict:
    """Get information from Mitre database.

    :param attack: Filters by attack ID
    :param phase: Filters by phase
    :param platform: Filters by platform
    :param search: Search if the string is contained in the db
    :param offset: First item to return
    :param limit: Maximum number of items to return
    :param sort: Sort the items. Format: {'fields': ['field1', 'field2'],
        'order': 'asc|desc'}
    :param q: Query to filter by
    :return: Dictionary with the data of the query from Mitre database
    """
    # replace field names in q parameter
    query = q.replace('attack', 'id').replace('phase', 'phase_name').replace(
        'platform', 'platform_name')

    if attack:
        query = f'{query};id={attack}' if query else f'id={attack}'
    if phase:
        query = f'{query};phase_name={phase}' if query else \
            f'phase_name={phase}'
    if platform:
        query = f'{query};platform_name={platform}' if query else \
                f'platform_name={platform}'

    db_query = WazuhDBQueryMitre(offset=offset, limit=limit if limit < 10
                                 else 10, query=query, sort=sort, 
                                 search={'negation': False, 'value': search})
    # execute query
    result = db_query.run()

    # parse JSON field (it returns as string from database)
    for item in result['items']:
        item['json'] = json.loads(item['json'])
        item['platforms'] = item['json']['x_mitre_platforms']
        item['phases'] = [elem['phase_name'] for elem in
                          item['json']['kill_chain_phases']]

    return result
