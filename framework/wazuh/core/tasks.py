# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

import json
from json import dumps, loads

import more_itertools

from wazuh.core import common
from wazuh.core.common import database_limit
from wazuh.core.exception import WazuhError
from wazuh.core.utils import WazuhDBQuery, \
    WazuhDBBackend
from wazuh.core.wazuh_socket import OssecSocket

tasks_fields = {'task_id': 'task_id', 'agent_id': 'agent_id', 'node': 'node', 'module': 'module',
                'command': 'command', 'create_time': 'create_time', 'last_update_time': 'last_update_time',
                'status': 'status', 'error_message': 'error_message'}
inner_select = 'DISTINCT(task_id)'
unique_fields = ['task_id']


class WazuhDBQueryTasks(WazuhDBQuery):

    def __init__(self, offset: int = 0, limit: int = common.database_limit, query: str = '', count: bool = True,
                 get_data: bool = True, table: str = 'tasks', sort: dict = None, default_sort_field: str = 'task_id',
                 fields=None, search: dict = None, select: dict = None, min_select_fields=None, filters=None):
        """Create an instance of WazuhDBQueryTasks query."""

        if filters is None:
            filters = {}
        if min_select_fields is None:
            min_select_fields = {'task_id', 'agent_id', 'status', 'command', 'create_time'}
        if fields is None:
            fields = tasks_fields

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table=table, sort=sort, search=search, select=select,
                              fields=fields, default_sort_field=default_sort_field, default_sort_order='ASC',
                              filters=filters, query=query, count=count, get_data=get_data,
                              min_select_fields=min_select_fields, backend=WazuhDBBackend(query_format='task'))

    def _final_query(self):
        """
        :return: The final tasks query
        """
        return self._default_query() + f" WHERE task_id IN ({self.query}) " + "LIMIT :limit OFFSET :offset"

    def _default_count_query(self):
        return "COUNT(DISTINCT task_id)"

    def _get_total_items(self):
        self.total_items = self.backend.execute(self.query.format(self._default_count_query()), self.request, True)

    def _add_limit_to_query(self):
        if self.limit:
            if self.limit > database_limit:
                raise WazuhError(1405, str(self.limit))

            # We add offset and limit only to the inner SELECT (subquery)
            self.query += ' LIMIT :inner_limit OFFSET :inner_offset'
            self.request['inner_offset'] = self.offset
            self.request['inner_limit'] = self.limit
            self.request['offset'] = 0
            self.request['limit'] = 0
        elif self.limit == 0:  # 0 is not a valid limit
            raise WazuhError(1406)

    def _execute_data_query(self):
        self.query = self.query.format(inner_select)
        self.query = self._final_query().format(','.join(map(lambda x: f"{self.fields[x]} as '{x}'",
                                                             self.select | self.min_select_fields)))

        self._data = self.backend.execute(self.query, self.request)


def send_to_tasks_socket(command):
    """Send command task module

    Parameters
    ----------
    command : dict
        Command to be send to task module

    Returns
    -------
    Message received from the socket
    """
    s = OssecSocket(common.TASKS_SOCKET)
    s.send(dumps(command).encode())
    data = loads(s.receive().decode())
    s.close()

    return data
