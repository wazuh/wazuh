# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

from datetime import datetime

from wazuh.core.utils import WazuhDBQuery, WazuhDBBackend


class WazuhDBQuerySyscheck(WazuhDBQuery):

    def __init__(self, agent_id, default_sort_field='mtime', *args, **kwargs):
        super().__init__(backend=WazuhDBBackend(agent_id), default_sort_field=default_sort_field, count=True,
                         get_data=True, date_fields={'mtime', 'date'}, *args, **kwargs)

    def _filter_date(self, date_filter, filter_db_name):
        # dates are stored as timestamps
        try:
            date_filter['value'] = int(datetime.timestamp(datetime.strptime(date_filter['value'], "%Y-%m-%d %H:%M:%S")))
        except ValueError:
            date_filter['value'] = int(datetime.timestamp(datetime.strptime(date_filter['value'], "%Y-%m-%d")))
        self.query += "{0} IS NOT NULL AND {0} {1} :{2}".format(self.fields[filter_db_name], date_filter['operator'],
                                                                date_filter['field'])
        self.request[date_filter['field']] = date_filter['value']

    def _format_data_into_dictionary(self):
        def format_fields(field_name, value):
            if field_name == 'mtime' or field_name == 'date':
                return datetime.utcfromtimestamp(value)
            if field_name == 'end' or field_name == 'start':
                return None if not value else datetime.utcfromtimestamp(value)
            else:
                return value

        self._data = [{key: format_fields(key, value) for key, value in item.items() if key in self.select}
                      for item in self._data]

        return super()._format_data_into_dictionary()
