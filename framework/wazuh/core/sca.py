# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

import re
from types import MappingProxyType

from wazuh.core.agent import Agent
from wazuh.core.utils import WazuhDBQuery, WazuhDBBackend, get_date_from_timestamp

RULES_API_FIELDS = {'rules.type', 'rules.rule'}
COMPLIANCE_API_FIELDS = {'compliance.key', 'compliance.value'}
SCA_CHECKS_API_FIELDS = {'policy_id', 'id', 'title', 'description', 'rationale', 'remediation', 'file', 'process',
                         'directory', 'registry', 'command', 'references', 'result', 'status', 'reason', 'condition'}

RULES_DB_FIELDS = {'type', 'rule'}
COMPLIANCE_DB_FIELDS = {'key', 'value'}
SCA_CHECKS_DB_FIELDS = {'policy_id', 'id', 'title', 'description', 'rationale', 'remediation', 'file', 'process',
                        'directory', 'registry', 'command', '`references`', 'result', '`status`', 'reason', 'condition'}


class WazuhDBQuerySCA(WazuhDBQuery):
    DEFAULT_QUERY = 'SELECT {0} FROM sca_policy sca INNER JOIN sca_scan_info si ON sca.id=si.policy_id'
    # API-DB fields mapping
    FIELDS_TRANSLATION = MappingProxyType(
        {'policy_id': 'policy_id', 'name': 'name', 'description': 'description', 'references': '`references`',
         'pass': 'pass', 'fail': 'fail', 'score': 'score', 'invalid': 'invalid', 'total_checks': 'total_checks',
         'hash_file': 'hash_file', 'end_scan': 'end_scan', 'start_scan': 'start_scan'})

    def __init__(self, agent_id, offset, limit, sort, search, query, count, get_data, select=None,
                 default_sort_field='policy_id', default_sort_order='DESC', filters=None, fields=None,
                 default_query=DEFAULT_QUERY, count_field='policy_id'):
        self.agent_id = agent_id
        self.default_query = default_query
        self.count_field = count_field
        Agent(agent_id).get_basic_information()  # check if the agent exists

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='sca_policy', sort=sort, search=search,
                              select=select or list(self.FIELDS_TRANSLATION.keys()),
                              fields=fields or self.FIELDS_TRANSLATION,
                              default_sort_field=default_sort_field, default_sort_order=default_sort_order,
                              filters=filters or {}, query=query, count=count, get_data=get_data,
                              date_fields={'end_scan', 'start_scan'}, backend=WazuhDBBackend(agent_id))

    def _default_query(self):
        return self.default_query

    def _default_count_query(self):
        return f"SELECT COUNT(DISTINCT {self.count_field})" + " FROM ({0})"

    def _format_data_into_dictionary(self):
        def format_fields(field_name, value):
            if field_name in ['end_scan', 'start_scan']:
                return get_date_from_timestamp(value)
            else:
                return value

        self._data = [{key: format_fields(key, value)
                       for key, value in item.items() if key in self.select} for item in self._data]

        return super()._format_data_into_dictionary()


class WazuhDBQuerySCACheck(WazuhDBQuerySCA):
    DEFAULT_QUERY = "SELECT {0} FROM sca_check"
    # API-DB fields mapping
    FIELDS_TRANSLATION = MappingProxyType(
        {'policy_id': 'policy_id', 'id': 'id', 'title': 'title', 'description': 'description', 'rationale': 'rationale',
         'remediation': 'remediation', 'file': 'file', 'process': 'process', 'directory': 'directory',
         'registry': 'registry', 'command': 'command', 'references': '`references`', 'result': 'result',
         'status': '`status`', 'reason': 'reason', 'condition': 'condition', 'rules.type': 'type', 'rules.rule': 'rule',
         'compliance.key': 'key', 'compliance.value': 'value', 'id_check': 'id_check'})
    SELECT_FIELDS = list(set(FIELDS_TRANSLATION.keys()) - RULES_API_FIELDS - COMPLIANCE_API_FIELDS - {'id_check'})

    def __init__(self, agent_id, offset, limit, sort, filters, search, query, policy_id):
        policy_query_filter = f"policy_id={policy_id}"

        WazuhDBQuerySCA.__init__(self, agent_id=agent_id, offset=offset, limit=limit, sort=sort, filters=filters,
                                 query=policy_query_filter if not query else f"{policy_query_filter};{query}",
                                 search=search, count=True, get_data=True, select=self.SELECT_FIELDS,
                                 default_query=self.DEFAULT_QUERY, fields=self.FIELDS_TRANSLATION, count_field='id',
                                 default_sort_field='id', default_sort_order='ASC')

    def _add_search_to_query(self):
        if self.search:
            # Do not take into account compliance and rules fields
            fields = [value for value in self.fields.values() if
                      value not in RULES_DB_FIELDS.union(COMPLIANCE_DB_FIELDS).union({'id_check'})]

            self.query += " AND NOT" if bool(self.search['negation']) else ' AND'
            self.query += " (" + " OR ".join(
                f'({x.split(" as ")[0]} LIKE :search AND {x.split(" as ")[0]} IS NOT NULL)' for x in fields) + ')'
            self.query = self.query.replace('WHERE  AND', 'WHERE')
            self.request['search'] = "%{0}%".format(re.sub(f"[{self.special_characters}]", '_', self.search['value']))


class WazuhDBQuerySCACheckRelational(WazuhDBQuerySCA):
    # API-DB fields mapping
    FIELDS_TRANSLATION = MappingProxyType(
        {'policy_id': 'policy_id', 'id': 'id', 'title': 'title', 'description': 'description', 'rationale': 'rationale',
         'remediation': 'remediation', 'file': 'file', 'process': 'process', 'directory': 'directory',
         'registry': 'registry', 'command': 'command', 'references': '`references`', 'result': 'result',
         'status': '`status`', 'reason': 'reason', 'condition': 'condition', 'rules.type': 'type', 'rules.rule': 'rule',
         'compliance.key': 'key', 'compliance.value': 'value', 'id_check': 'id_check'})
    SELECT_FIELDS = set(FIELDS_TRANSLATION.keys()) - SCA_CHECKS_API_FIELDS

    def __init__(self, agent_id, table, id_check_list=None, search=None, query=""):
        self.sca_check_table = table
        default_query = "SELECT {0} FROM " + self.sca_check_table
        if id_check_list:
            default_query += f" WHERE id_check IN {str(id_check_list).replace('[', '(').replace(']', ')')}"
        select = self.SELECT_FIELDS - COMPLIANCE_API_FIELDS if self.sca_check_table == 'sca_check_rules' \
            else self.SELECT_FIELDS - RULES_API_FIELDS

        WazuhDBQuerySCA.__init__(self, agent_id=agent_id, default_query=default_query,
                                 fields=self.FIELDS_TRANSLATION, offset=0, limit=None, sort=None, search=search,
                                 select=list(select), query=query, count=False, get_data=True,
                                 default_sort_field='id_check', default_sort_order='ASC')

    def _add_search_to_query(self):
        if self.search:
            # Do not take into account compliance and rules fields
            fields_to_delete = SCA_CHECKS_DB_FIELDS.union(RULES_DB_FIELDS) \
                if self.sca_check_table == 'sca_check_compliance' else SCA_CHECKS_DB_FIELDS.union(COMPLIANCE_DB_FIELDS)
            fields = [value for value in self.fields.values() if value not in fields_to_delete]

            self.query += " AND NOT" if bool(self.search['negation']) else ' AND'
            self.query += " (" + " OR ".join(
                f'({x.split(" as ")[0]} LIKE :search AND {x.split(" as ")[0]} IS NOT NULL)' for x in fields) + ')'
            self.query = self.query.replace('WHERE  AND', 'WHERE')
            self.request['search'] = "%{0}%".format(re.sub(f"[{self.special_characters}]", '_', self.search['value']))
