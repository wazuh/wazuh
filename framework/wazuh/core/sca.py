# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

from types import MappingProxyType
from typing import Union

from wazuh.core.agent import Agent
from wazuh.core.utils import WazuhDBQuery, WazuhDBBackend, get_date_from_timestamp

# API-DB fields mapping
SCA_CHECK_DB_FIELDS = MappingProxyType(
    {'policy_id': 'policy_id', 'id': 'id', 'title': 'title', 'description': 'description', 'rationale': 'rationale',
     'remediation': 'remediation', 'file': 'file', 'process': 'process', 'directory': 'directory',
     'registry': 'registry', 'command': 'command', 'references': '`references`', 'result': 'result',
     'status': '`status`', 'reason': 'reason', 'condition': 'condition'})

SCA_CHECK_COMPLIANCE_DB_FIELDS = MappingProxyType(
    {'compliance.key': 'key', 'compliance.value': 'value', 'id_check': 'id_check'})

SCA_CHECK_RULES_DB_FIELDS = MappingProxyType(
    {'rules.type': 'type', 'rules.rule': 'rule', 'id_check': 'id_check'})


class WazuhDBQuerySCA(WazuhDBQuery):
    """Class used to query SCA items."""

    DEFAULT_QUERY = 'SELECT {0} FROM sca_policy sca INNER JOIN sca_scan_info si ON sca.id=si.policy_id'
    # API-DB fields mapping
    DB_FIELDS = MappingProxyType(
        {'policy_id': 'policy_id', 'name': 'name', 'description': 'description', 'references': '`references`',
         'pass': 'pass', 'fail': 'fail', 'score': 'score', 'invalid': 'invalid', 'total_checks': 'total_checks',
         'hash_file': 'hash_file', 'end_scan': 'end_scan', 'start_scan': 'start_scan'})

    def __init__(self, agent_id: str, offset: int, limit: Union[int, None], sort: Union[dict, None],
                 search: Union[dict, None], query: Union[str, None], count: bool, get_data: bool, select: list = None,
                 default_sort_field: str = 'policy_id', default_sort_order: str = 'DESC', filters: dict = None,
                 fields: dict = None, default_query: str = DEFAULT_QUERY, count_field: str = 'policy_id'):
        """Class constructor.

        Parameters
        ----------
        agent_id : str
            Agent ID.
        offset : int
            First item to return.
        limit : int or None
            Maximum number of items to return.
        sort : dict or None
            Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        select : list
            Select fields to return. Format: ["field1","field2"].
        search : dict or None
            Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
        filters : dict
            Defines field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}
        query : str or None
            Query to filter in database. Format: field operator value.
        default_sort_field : str
            By default, return elements sorted by this field. Default: 'policy_id'
        default_sort_order : str
            Default order when sorting. Default: 'DESC'
        count : bool
            Whether to compute totalItems or not.
        get_data : bool
            Whether to return data or not.
        fields : dict
            SCA fields.
        default_query : str
            Default query. Default: DEFAULT_QUERY
        count_field : str
            Field to apply count. Default: 'policy_id'
        """
        self.agent_id = agent_id
        self.default_query = default_query
        self.count_field = count_field
        Agent(agent_id).get_basic_information()  # check if the agent exists

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='sca_policy', sort=sort, search=search,
                              select=list(self.DB_FIELDS.keys()) if select is None else select,
                              fields=fields or self.DB_FIELDS, default_sort_field=default_sort_field,
                              default_sort_order=default_sort_order, filters=filters or {}, query=query, count=count,
                              get_data=get_data, date_fields={'end_scan', 'start_scan'},
                              backend=WazuhDBBackend(agent_id))

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
    """Class used to get SCA checks items."""

    def __init__(self, agent_id: str, sort: dict, sca_checks_ids: list):
        """Class constructor.

        Parameters
        ----------
        agent_id : str
            Agent ID.
        sort : dict
            Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        sca_checks_ids : list
            List used to filter SCA checks by ID.
        """
        default_query = "SELECT {0} FROM sca_check"
        if sca_checks_ids:
            default_query += f" WHERE id IN {str(sca_checks_ids).replace('[', '(').replace(']', ')')}"

        WazuhDBQuerySCA.__init__(self, agent_id=agent_id, offset=0, limit=None, sort=sort, filters={},
                                 search=None, count=False, get_data=True,
                                 select=list(SCA_CHECK_DB_FIELDS.keys()), default_query=default_query,
                                 fields=SCA_CHECK_DB_FIELDS, count_field='id', default_sort_field='id',
                                 default_sort_order='ASC', query='')


class WazuhDBQuerySCACheckIDs(WazuhDBQuerySCA):
    """Class used to get SCA checks IDs from the main SCA checks table joining compliance and rules items."""

    DEFAULT_QUERY = "SELECT DISTINCT(id) FROM sca_check a LEFT JOIN sca_check_compliance b ON a.id=b.id_check " \
                    "LEFT JOIN sca_check_rules c ON a.id=c.id_check"

    def __init__(self, agent_id: str, offset: int, limit: int, filters: dict, search: Union[dict, None], query: str,
                 policy_id: str):
        """Class constructor.

        Parameters
        ----------
        agent_id : str
            Agent ID.
        offset : int
            First item to return.
        limit : int or None
            Maximum number of items to return.
        search : dict or None
            Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
        filters : dict
            Defines field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}
        query : str
            Query to filter in database. Format: field operator value.
        policy_id : str
            Filter by SCA policy ID.
        """
        policy_query_filter = f"policy_id={policy_id}"
        fields = SCA_CHECK_DB_FIELDS | SCA_CHECK_COMPLIANCE_DB_FIELDS | SCA_CHECK_RULES_DB_FIELDS
        fields.pop('id_check')

        WazuhDBQuerySCA.__init__(self, agent_id=agent_id, offset=offset, limit=limit, sort=None, filters=filters,
                                 query=policy_query_filter if not query else f"{policy_query_filter};{query}",
                                 search=search, count=True, get_data=True, select=[],
                                 default_query=self.DEFAULT_QUERY, fields=fields, count_field='id',
                                 default_sort_field='id', default_sort_order='ASC')

    def _default_count_query(self):
        return "SELECT COUNT(*) FROM ({0})"


class WazuhDBQuerySCACheckRelational(WazuhDBQuerySCA):
    """Class used to get SCA rules or compliance items related to a given SCA checks IDs list."""

    FIELDS_PER_TABLE = MappingProxyType({'sca_check_rules': SCA_CHECK_RULES_DB_FIELDS,
                                         'sca_check_compliance': SCA_CHECK_COMPLIANCE_DB_FIELDS})

    def __init__(self, agent_id: str, table: str, id_check_list: list):
        """Class constructor.

        Parameters
        ----------
        agent_id : str
            Agent ID.
        table : str
            SCA check rules or compliance table. The value for this parameter must be 'sca_check_rules' or
            'sca_check_compliance'.
        id_check_list : list
            List used to filter rules or compliance by ID.
        """
        self.sca_check_table = table
        default_query = "SELECT {0} FROM " + self.sca_check_table
        if id_check_list:
            default_query += f" WHERE id_check IN {str(id_check_list).replace('[', '(').replace(']', ')')}"

        WazuhDBQuerySCA.__init__(self, agent_id=agent_id, default_query=default_query,
                                 fields=self.FIELDS_PER_TABLE[self.sca_check_table], offset=0, limit=None, sort=None,
                                 select=list(self.FIELDS_PER_TABLE[self.sca_check_table].keys()), count=False,
                                 get_data=True, default_sort_field='id_check', default_sort_order='ASC', query=None,
                                 search=None)
