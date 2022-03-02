# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

from json import loads, JSONDecodeError

from wazuh.core.utils import WazuhDBQuery, WazuhDBBackend, get_fields_to_nest, plain_dict_to_nested_dict, \
    get_date_from_timestamp
from wazuh.core.wdb import WazuhDBConnection


class WazuhDBQuerySyscheck(WazuhDBQuery):
    nested_fields = ['value']
    date_fields = {'start', 'end', 'mtime', 'date'}

    def __init__(self, agent_id, nested=False, default_sort_field='mtime', min_select_fields=None, *args,
                 **kwargs):
        if min_select_fields is None:
            min_select_fields = set()
        super().__init__(backend=WazuhDBBackend(agent_id), default_sort_field=default_sort_field,
                         min_select_fields=min_select_fields, count=True, get_data=True, date_fields=self.date_fields,
                         *args, **kwargs)
        self.nested = nested

    def _format_data_into_dictionary(self):
        def format_fields(field_name, value):
            if field_name in self.date_fields:
                return None if not value else get_date_from_timestamp(value)
            elif field_name == 'perm':
                try:
                    return loads(value)
                except JSONDecodeError:
                    return value
            else:
                return value

        self._data = [{key: format_fields(key, value) for key, value in item.items()} for item in self._data]

        if self.nested:
            fields_to_nest, non_nested = get_fields_to_nest(self.fields.keys(), self.nested_fields, '.')
            self._data = [plain_dict_to_nested_dict(d, fields_to_nest, non_nested, self.nested_fields, '.') for d in
                          self._data]

        return super()._format_data_into_dictionary()


def syscheck_delete_agent(agent: str, wdb_conn: WazuhDBConnection) -> None:
    wdb_conn.execute(f"agent {agent} sql delete from fim_entry", delete=True)
