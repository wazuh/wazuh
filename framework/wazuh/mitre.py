# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import re
from typing import Dict

import more_itertools

from wazuh.common import database_limit
from wazuh.exception import WazuhException
from wazuh.utils import WazuhDBBackend, WazuhDBQuery

mitre_fields = {'id': 'id', 'json': 'json', 'phase_name': 'phase_name', 'platform_name': 'platform_name'}
from_fields = "attack LEFT JOIN has_phase ON attack.id = has_phase.attack_id" \
              " LEFT JOIN has_platform ON attack.id = has_platform.attack_id"
unique_fields = ['id', 'json']
inner_select = 'DISTINCT(id)'


class WazuhDBQueryMitre(WazuhDBQuery):
    """Create a WazuhDB query for getting data from Mitre database."""

    def __init__(self, offset: int = 0, limit: int = 10, query: str = '', count: bool = True, get_data: bool = True,
                 table: str = 'attack', sort: dict = None, default_sort_field: str = 'id', fields: dict = mitre_fields,
                 search: dict = None, select: dict = None, min_select_fields={'id'}):
        """Create an instance of WazuhDBQueryMitre query."""

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table=table, sort=sort, search=search, select=select,
                              fields=fields, default_sort_field=default_sort_field, default_sort_order='ASC',
                              filters=None, query=query, count=count, get_data=get_data,
                              min_select_fields=min_select_fields, backend=WazuhDBBackend(query_format='mitre'))

    def _default_query(self):
        """
        :return: The default query
        """
        return "SELECT {0} FROM " + f"{from_fields}"

    def _final_query(self):
        """
        :return: The final mitre query
        """
        return self._default_query() + f" WHERE id IN ({self.query}) " + "LIMIT :limit OFFSET :offset"

    def _default_count_query(self):
        return "COUNT(DISTINCT id)"

    def _add_limit_to_query(self):
        if self.limit:
            if self.limit > database_limit:
                raise WazuhException(1405, str(self.limit))

            # We add offset and limit only to the inner SELECT (subquery)
            self.query += ' LIMIT :inner_limit OFFSET :inner_offset'
            self.request['inner_offset'] = self.offset
            self.request['inner_limit'] = self.limit
            self.request['offset'] = 0
            self.request['limit'] = 0
        elif self.limit == 0:  # 0 is not a valid limit
            raise WazuhException(1406)

    def _execute_data_query(self):
        self.query = self.query.format(inner_select)
        self.query = self._final_query().format(','.join(map(lambda x: f"{self.fields[x]} as '{x}'",
                                                             self.select['fields'] | self.min_select_fields)))

        self._data = self.backend.execute(self.query, self.request)

    def _format_data_into_dictionary(self):
        result = list()
        # We construct result from the query data
        for entry in self._data:
            try:
                # We find if we already have a dict with this id
                found_in_pos = list(more_itertools.locate(result, pred=lambda d: d['id'] == entry['id']))[0]
                for k, v in entry.items():
                    if k not in unique_fields and v not in result[found_in_pos][k]:
                        # We append the fields to their corresponding dict if id is already present
                        result[found_in_pos][k].append(v)
            except IndexError:
                # We format and add a dict to result if id was not found
                result.append(
                    {k: (json.loads(v) if k == 'json' else v) if k in unique_fields else [v] for k, v in entry.items()})
        self._data = result
        return super()._format_data_into_dictionary()


def get_attack(attack: str = None, phase: str = None, platform: str = None, select: dict = None, search: dict = None,
               offset: int = 0, limit: int = None, sort: dict = None, q: str = None, ) -> Dict:
    """Get information from Mitre database.

    :param attack: Filters by attack ID
    :param phase: Filters by phase
    :param platform: Filters by platform
    :param search: Search if the string is contained in the db
    :param offset: First item to return
    :param limit: Maximum number of items to return
    :param sort: Sort the items. Format: {'fields': ['field1', 'field2'], 'order': 'asc|desc'}
    :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
    :param q: Query to filter by
    :return: Dictionary with the data of the query from Mitre database
    """
    # Set default limit to 500 if json is not selected and 10 otherwise in order to avoid congesting wdb socket
    default_limit = 10 if select is None or 'json' in select['fields'] else 500
    limit = min(limit, default_limit) if limit is not None else default_limit

    # Replace filter names in q parameter only if they are followed by an operator
    if q:
        filters = {'attack': 'id', 'phase': 'phase_name', 'platform': 'platform_name'}
        for filter_, substitute in filters.items():
            try:
                q = re.sub(re.search(rf'({filter_})(=|!=|<|>|~)', q).group(1), substitute, q)
            except AttributeError:
                pass

    # Add regular field filters to q
    if attack:
        q = f'{q};id={attack}' if q else f'id={attack}'
    if phase:
        q = f'{q};phase_name={phase}' if q else f'phase_name={phase}'
    if platform:
        q = f'{q};platform_name={platform}' if q else f'platform_name={platform}'

    # Execute query
    db_query = WazuhDBQueryMitre(offset=offset, limit=limit, query=q, sort=sort, search=search, select=select)
    result = db_query.run()

    return result
