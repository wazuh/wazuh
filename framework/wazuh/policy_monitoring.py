#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from glob import glob
from itertools import groupby


from wazuh import common
from wazuh.agent import Agent
from wazuh.exception import WazuhException
from wazuh.utils import WazuhDBQuery
from wazuh.wdb import WazuhDBConnection


# API field -> DB field
fields_translation_pm = {'scan_id': 'scan_id',
                         'name': 'name',
                         'description': 'description',
                         'os_required': 'os_required',
                         'pass': 'pass',
                         'failed': 'failed',
                         'score': 'score',
                         'end_scan': 'pm_end_scan',
                         'start_scan': 'pm_start_scan'}
fields_translation_pm_check = {'name': 'name',
                               'id': 'id',
                               'cis': 'cis_control',
                               'title': 'title',
                               'description': 'description',
                               'rationale': 'rationale',
                               'remediation': 'remediation',
                               'default_value': 'default_value',
                               'file': 'file',
                               'process': 'process',
                               'directory': 'directory',
                               'registry': 'registry',
                               'reference': 'reference',
                               'result': 'result'}
fields_translation_pm_check_compliance = {'key': 'key',
                                          'value': 'value'}

default_query_pm = 'SELECT {0} FROM pm_global pmg INNER JOIN scan_info si ON pmg.scan_id=si.pm_scan_id'
default_query_pm_check = 'SELECT {0} FROM pm_check INNER JOIN pm_check_compliance ON id=id_check'


class WazuhDBQueryPM(WazuhDBQuery):

    def __init__(self, agent_id, offset, limit, sort, search, select, query, count,
                 get_data, default_sort_field='name', filters={}, fields=fields_translation_pm,
                 default_query=default_query_pm):
        self.agent_id = agent_id
        self._default_query_str = default_query
        Agent(agent_id).get_basic_information()  # check if the agent exists
        db_path = glob('{0}/{1}.db'.format(common.wdb_path, agent_id))
        if not db_path:
            raise WazuhException(1600)

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='pm_global', sort=sort, search=search,
                              select=select, fields=fields, default_sort_field=default_sort_field,
                              default_sort_order='DESC', filters=filters, query=query, db_path=db_path[0],
                              min_select_fields=set(), count=count, get_data=get_data,
                              date_fields={'pm_end_scan', 'pm_start_scan'})
        self.conn = WazuhDBConnection()

    def _default_query(self):
        return self._default_query_str

    def _substitute_params(self):
        for k, v in self.request.items():
            self.query = self.query.replace(f':{k}', str(v))

    def _get_total_items(self):
        self._substitute_params()
        self.total_items = self.conn.execute(f'agent {self.agent_id} sql ' + self.query.format(self._default_count_query()))

    def _get_data(self):
        self._substitute_params()
        self._data = self.conn.execute(f'agent {self.agent_id} sql '
                                       + self.query.format(','.join(map(lambda x: self.fields[x],
                                                                        self.select['fields'] | self.min_select_fields)
                                                                    )
                                                           )
                                       )

    def _format_data_into_dictionary(self):
        return self._data

    def run(self):

        self._add_select_to_query()
        self._add_filters_to_query()
        self._add_search_to_query()
        if self.count:
            self._get_total_items()
        self._add_sort_to_query()
        self._add_limit_to_query()
        if self.data:
            self._get_data()
            return self._format_data_into_dictionary()


def get_pm_list(agent_id=None, q="", offset=0, limit=common.database_limit,
                sort=None, search=None, select=None, filters={}):
    if select is None:
        select = {'fields': list(fields_translation_pm.keys())}

    db_query = WazuhDBQueryPM(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                              select=select, count=True, get_data=True, query=q, filters=filters)
    return db_query.run()


def get_pm_checks(name, agent_id=None, q="", offset=0, limit=common.database_limit,
                  sort=None, search=None, select=None, filters={}):
    fields_translation = {**fields_translation_pm_check,
                          **fields_translation_pm_check_compliance}
    if select is None:
        select = {'fields': (list(fields_translation_pm_check.keys()) +
                             list(fields_translation_pm_check_compliance.keys()))
                  }
    else:
        if 'name' not in select['fields']:
            select['fields'].append('name')

    db_query = WazuhDBQueryPM(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                              select=select, count=True, get_data=True,
                              query=f'name={name}' if q == "" else f'name={name};{q}',
                              filters=filters, default_query=default_query_pm_check,
                              fields=fields_translation)

    checks = db_query.run()
    groups = groupby(checks, key=lambda row: row['name'])
    result = []
    # Rearrange check and compliance fields
    for _, group in groups:
        group_list = list(group)
        check_dict = {k: v for k, v in group_list[0].items() if k in fields_translation_pm_check.values()}
        check_dict['compliance'] = [{k: v for k, v in elem.items()
                                     if k in fields_translation_pm_check_compliance.values()}
                                    for elem in group_list
                                    ]
        result.append(check_dict)

    return result
