#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Framework module for getting information from Wazuh MITRE database."""

from wazuh import common
from wazuh.exception import WazuhException
from wazuh.utils import WazuhDBQuery, WazuhDBBackend

field_translations_mitre_attack = {'id': 'id',
                                   'json': 'json'}

fields_translation_mitre_has_phase = {'attack_id': 'attack_id',
                                      'has_phase': 'has_phase'}

fields_translation_mitre_has_platform = {'attack_id': 'attack_id',
                                         'platform_name': 'platform_name'}

default_query_mitre = 'SELECT {0} FROM attack'


class WazuhDBQueryMitre(WazuhDBQuery):
    """Create a WazuhDB query for getting data from Mitre database."""

    def __init__(self, offset, limit, sort, search, select, query,
                 count, get_data, default_query=default_query_mitre,
                 default_sort_field='attack_id', filters={},
                 fields=field_translations_mitre_attack,
                 count_field='attack_id'):
        """Create an instance of WazuhDBQueryMitre query."""
        self.default_query = default_query
        self.count_field = count_field

        WazuhDBQuery.__init__(self, offset=offset, limit=limit,
                              table='attack', sort=sort, search=search,
                              select=select, fields=fields,
                              default_sort_field=default_sort_field,
                              default_sort_order='DESC', filters=filters,
                              query=query, count=count, get_data=get_data,
                              date_fields={'end_scan', 'start_scan'},
                              backend=WazuhDBBackend())

    def _default_query(self):
        return self.default_query

    def _default_count_query(self):
        return f"COUNT(DISTINCT {self.count_field})"

    def execute(self, query, request, count=False):
        """Execute a query in WazuhDB for getting data from Mitre database."""
        query = self._substitute_params(query, request)
        return self.conn.execute(query=f'mitre sql {query}',
                                 count=count)


def get_mitre_data(q="", offset=0, limit=10, sort=None, search=None,
                   filters={}):
    """Get data from Mitre database."""
    db_query = WazuhDBQueryMitre(offset=offset, limit=common.database_limit,
                                 sort=sort, search=search, select=None,
                                 count=True, get_data=True, query=q,
                                 filters=filters)

    return db_query.run()
