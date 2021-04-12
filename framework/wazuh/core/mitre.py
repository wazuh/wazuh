# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

from wazuh.core import common
from wazuh.core.utils import WazuhDBQuery, WazuhDBBackend


class WazuhDBQueryMitre(WazuhDBQuery):

    def __init__(self, offset: int = 0, limit: int = common.database_limit, query: str = '', count: bool = True,
                 get_data: bool = True, table: str = 'technique', sort: dict = None, default_sort_field: str = 'key',
                 default_sort_order='ASC', fields=None, search: dict = None, select: dict = None,
                 min_select_fields=None, filters=None):
        """Create an instance of WazuhDBQueryMitre query."""

        if filters is None:
            filters = {}

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table=table, sort=sort, search=search, select=select,
                              fields=fields, default_sort_field=default_sort_field,
                              default_sort_order=default_sort_order, filters=filters, query=query, count=count,
                              get_data=get_data, min_select_fields=min_select_fields,
                              backend=WazuhDBBackend(query_format='mitre'))

    def _filter_status(self, status_filter):
        pass


class WazuhDBQueryMitreMetadata(WazuhDBQueryMitre):

    def __init__(self):
        """Create an instance of WazuhDBQueryMitreMetadata query."""

        min_select_fields = {'key', 'value'}
        fields = {'key': 'key', 'value': 'value'}

        WazuhDBQueryMitre.__init__(self, table='metadata', min_select_fields=min_select_fields, fields=fields)

    def _filter_status(self, status_filter):
        pass
