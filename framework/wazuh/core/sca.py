# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

import re
from datetime import datetime

from wazuh.core.agent import Agent
from wazuh.core.common import database_limit
from wazuh.core.exception import WazuhError
from wazuh.core.utils import WazuhDBQuery, WazuhDBBackend

# API field -> DB field
fields_translation_sca = {'policy_id': 'policy_id',
                          'name': 'name',
                          'description': 'description',
                          'references': '`references`',
                          'pass': 'pass',
                          'fail': 'fail',
                          'score': 'score',
                          'invalid': 'invalid',
                          'total_checks': 'total_checks',
                          'hash_file': 'hash_file',
                          'end_scan': 'end_scan',
                          'start_scan': 'start_scan'
                          }
fields_translation_sca_check = {'policy_id': 'policy_id',
                                'id': 'id',
                                'title': 'title',
                                'description': 'description',
                                'rationale': 'rationale',
                                'remediation': 'remediation',
                                'file': 'file',
                                'process': 'process',
                                'directory': 'directory',
                                'registry': 'registry',
                                'command': 'command',
                                'references': '`references`',
                                'result': 'result',
                                'status': '`status`',
                                'reason': 'reason',
                                'condition': 'condition'}
fields_translation_sca_check_compliance = {'compliance.key': 'key',
                                           'compliance.value': 'value'}
fields_translation_sca_check_rule = {'rules.type': 'type', 'rules.rule': 'rule'}

default_query_sca = 'SELECT {0} FROM sca_policy sca INNER JOIN sca_scan_info si ON sca.id=si.policy_id'
default_query_sca_check = 'SELECT {0} FROM sca_check a LEFT JOIN sca_check_compliance b ON a.id=b.id_check ' \
                          'LEFT JOIN sca_check_rules c ON a.id=c.id_check WHERE id IN (SELECT id FROM sca_check)'


class WazuhDBQuerySCA(WazuhDBQuery):

    def __init__(self, agent_id, offset, limit, sort, search, select, query, count,
                 get_data, default_sort_field='policy_id', filters=None, fields=fields_translation_sca,
                 default_query=default_query_sca, count_field='policy_id'):
        self.agent_id = agent_id
        self.default_query = default_query
        self.count_field = count_field
        Agent(agent_id).get_basic_information()  # check if the agent exists
        filters = {} if filters is None else filters

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='sca_policy', sort=sort,
                              search=search, select=select, fields=fields, default_sort_field=default_sort_field,
                              default_sort_order='DESC', filters=filters, query=query, count=count, get_data=get_data,
                              date_fields={'end_scan', 'start_scan'}, backend=WazuhDBBackend(agent_id))

    def _default_query(self):
        return self.default_query

    def _default_count_query(self):
        return f"SELECT COUNT(DISTINCT {self.count_field})" + " FROM ({0})"

    def _process_filter(self, field_name, field_filter, q_filter):
        if field_name in self.date_fields and not isinstance(q_filter['value'], (int, float)):
            # Filter a date, but only if it is in string (YYYY-MM-DD hh:mm:ss) format.
            # If it matches the same format as DB (timestamp integer), filter directly by value (next if cond).
            self._filter_date(q_filter, field_name)
        else:
            if q_filter['value'] is not None:
                self.request[field_filter] = q_filter['value'] if field_name != "version" else re.sub(
                    r'([a-zA-Z])([v])', r'\1 \2', q_filter['value'])
                if q_filter['operator'] == 'LIKE' and q_filter['field'] not in self.wildcard_equal_fields:
                    self.request[field_filter] = "%{}%".format(self.request[field_filter])
                self.query += '{} {} :{}'.format(self.fields[field_name].split(' as ')[0], q_filter['operator'],
                                                 field_filter)
                if not field_filter.isdigit():
                    # filtering without being uppercase/lowercase sensitive
                    self.query += ' COLLATE NOCASE'
            else:
                self.query += '{} IS null'.format(self.fields[field_name])

    def _format_data_into_dictionary(self):
        def format_fields(field_name, value):
            if field_name in ['end_scan', 'start_scan']:
                return datetime.utcfromtimestamp(value)
            else:
                return value

        self._data = [{key: format_fields(key, value)
                       for key, value in item.items() if key in self.select} for item in self._data]

        return super()._format_data_into_dictionary()


class WazuhDBQuerySCACheck(WazuhDBQuerySCA):

    def _parse_filters(self):
        if self.legacy_filters:
            self._parse_legacy_filters()
        if self.q:
            self._parse_query()
        if self.search or self.query_filters:
            self.query += " WHERE " if self.query.count('WHERE') == 1 else ' AND '

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

    def run(self):
        """Builds the query and runs it on the database"""
        # Remove the last )
        self.query = self.query[:-1]

        self._add_select_to_query()
        self._add_filters_to_query()
        self._add_search_to_query()

        # Add the last )
        self.query += ")"
        if self.count:
            self._get_total_items()
            if not self.data:
                return {'totalItems': self.total_items}

        # Remove the last )
        self.query = self.query[:-1]
        self._add_limit_to_query()

        # Add the last )
        self.query += ")"
        self._add_sort_to_query()
        if self.data:
            self._execute_data_query()
            return self._format_data_into_dictionary()
