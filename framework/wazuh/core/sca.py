# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

from wazuh.core.utils import WazuhDBQuery, WazuhDBBackend
from wazuh.core.agent import Agent
from datetime import datetime

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
                          'LEFT JOIN sca_check_rules c ON a.id=c.id_check'


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

    def _format_data_into_dictionary(self):
        def format_fields(field_name, value):
            if field_name in ['end_scan', 'start_scan']:
                return datetime.utcfromtimestamp(value)
            else:
                return value

        self._data = [{key: format_fields(key, value)
                      for key, value in item.items() if key in self.select} for item in self._data]

        return super()._format_data_into_dictionary()
