# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

from datetime import datetime
from json import dumps, loads

from wazuh.core import common
from wazuh.core.exception import WazuhInternalError
from wazuh.core.utils import WazuhDBQuery, \
    WazuhDBBackend
from wazuh.core.wazuh_socket import WazuhSocket

tasks_fields = {'task_id': 'task_id', 'agent_id': 'agent_id', 'node': 'node', 'module': 'module',
                'command': 'command', 'create_time': 'create_time', 'last_update_time': 'last_update_time',
                'status': 'status', 'error_message': 'error_message'}


class WazuhDBQueryTask(WazuhDBQuery):

    def __init__(self, offset: int = 0, limit: int = common.database_limit, query: str = '', count: bool = True,
                 get_data: bool = True, table: str = 'tasks', sort: dict = None, default_sort_field: str = 'task_id',
                 fields=None, search: dict = None, select: dict = None, min_select_fields=None, filters=None):
        """Create an instance of WazuhDBQueryTasks query."""

        if filters is None:
            filters = {}
        if min_select_fields is None:
            min_select_fields = {'task_id'}
        if fields is None:
            fields = tasks_fields

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table=table, sort=sort, search=search, select=select,
                              fields=fields, default_sort_field=default_sort_field, default_sort_order='ASC',
                              filters=filters, query=query, count=count, get_data=get_data,
                              date_fields={'create_time', 'last_update_time'},
                              min_select_fields=min_select_fields, backend=WazuhDBBackend(query_format='task'))

    def _final_query(self):
        """
        :return: The final tasks query
        """
        return self._default_query() + f" WHERE task_id IN ({self.query}) " + "LIMIT :limit OFFSET :offset"

    def _process_filter(self, field_name, field_filter, q_filter):
        if 'agent_list' in field_name:
            self.query += f"agent_id {q_filter['operator']} (:{field_filter})"
            self.request[field_filter] = q_filter['value']
        elif 'task_list' in field_name:
            self.query += f"task_id {q_filter['operator']} (:{field_filter})"
            self.request[field_filter] = q_filter['value']
        else:
            super()._process_filter(field_name, field_filter, q_filter)

    def _format_data_into_dictionary(self):
        """Standardization of dates to the ISO 8601 format."""
        for t in self._data:
            if t.keys() >= {'create_time', 'last_update_time'}:
                t['create_time'] = datetime.utcfromtimestamp(t['create_time']).strftime("%Y-%m-%dT%H:%M:%SZ")
                t['last_update_time'] = datetime.utcfromtimestamp(t['last_update_time']).strftime("%Y-%m-%dT%H:%M:%SZ")

        return {'items': self._data, 'totalItems': self.total_items}


def send_to_tasks_socket(command):
    """Send command to task module

    Parameters
    ----------
    command : dict
        Command to be sent to task module

    Returns
    -------
    Message received from the socket
    """
    try:
        s = WazuhSocket(common.TASKS_SOCKET)
    except Exception:
        raise WazuhInternalError(1121)
    s.send(dumps(command).encode())
    data = loads(s.receive().decode())
    s.close()

    return data
