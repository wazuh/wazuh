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
fields_translation_ca = {'policy_id': 'policy_id',
                         'name': 'name',
                         'description': 'description',
                         'references': '`references`',
                         'pass': 'pass',
                         'fail': 'fail',
                         'score': 'score',
                         'end_scan': 'end_scan',
                         'start_scan': 'start_scan'
                         }
fields_translation_ca_check = {'policy_id': 'policy_id',
                               'id': 'id',
                               'title': 'title',
                               'description': 'description',
                               'rationale': 'rationale',
                               'remediation': 'remediation',
                               'file': 'file',
                               'process': 'process',
                               'directory': 'directory',
                               'registry': 'registry',
                               'references': '`references`',
                               'result': 'result'}
fields_translation_ca_check_compliance = {'key': 'key',
                                          'value': 'value'}

default_query_ca = 'SELECT {0} FROM configuration_assessment_policy ca INNER JOIN configuration_assessment_scan_info si ON ca.id=si.policy_id'
default_query_ca_check = 'SELECT {0} FROM configuration_assessment_check INNER JOIN configuration_assessment_check_compliance ON id=id_check'


class WazuhDBQueryPM(WazuhDBQuery):

    def __init__(self, agent_id, offset, limit, sort, search, select, query, count,
                 get_data, default_sort_field='policy_id', filters={}, fields=fields_translation_ca,
                 default_query=default_query_ca, count_field='policy_id'):
        self.agent_id = agent_id
        self._default_query_str = default_query
        self.count_field = count_field
        Agent(agent_id).get_basic_information()  # check if the agent exists
        db_path = glob('{0}/{1}.db'.format(common.wdb_path, agent_id))
        if not db_path:
            raise WazuhException(1600)

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='configuration_assessment_policy', sort=sort,
                              search=search, select=select, fields=fields, default_sort_field=default_sort_field,
                              default_sort_order='DESC', filters=filters, query=query, db_path=db_path[0],
                              min_select_fields=set(), count=count, get_data=get_data,
                              date_fields={'end_scan', 'start_scan'})
        self.conn = WazuhDBConnection()

    def _default_query(self):
        return self._default_query_str

    def _substitute_params(self):
        for k, v in self.request.items():
            self.query = self.query.replace(f':{k}', str(v))

    def _get_total_items(self):
        self._substitute_params()
        total_items = self.conn.execute(f'agent {self.agent_id} sql ' + self.query.format(self._default_count_query()))
        self.total_items = total_items if isinstance(total_items, int) else total_items[0][self._default_count_query()]

    def _default_count_query(self):
        return f"COUNT(DISTINCT {self.count_field})"

    def _get_data(self):
        self._substitute_params()
        self._data = self.conn.execute(f'agent {self.agent_id} sql '
                                       + self.query.format(','.join(map(lambda x: self.fields[x],
                                                                        self.select['fields'] | self.min_select_fields)
                                                                    )
                                                           )
                                       )

    def _format_data_into_dictionary(self):
        return {"totalItems": self.total_items, "items": self._data}

    def _parse_select_filter(self, select_fields):
        WazuhDBQuery._parse_select_filter(self, select_fields)
        for field in select_fields:
            if field in self.date_fields:
                select_fields[field] = f"strftime('%Y-%m-%d %H:%M:%S', datetime({field}, 'unixepoch')) as {field}"

        return select_fields

    def _add_limit_to_query(self):
        if self.limit:
            if self.limit > common.maximum_database_limit:
                raise WazuhException(1405, str(self.limit))
            self.query += ' LIMIT :limit OFFSET :offset'
            self.request['offset'] = self.offset
            self.request['limit'] = self.limit
        elif self.limit == 0:  # 0 is not a valid limit
            raise WazuhException(1406)

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


def get_ca_list(agent_id=None, q="", offset=0, limit=common.database_limit,
                sort=None, search=None, select=None, filters={}):
    """
    Gets a list of policies analized in the configuration assessment
    :param agent_id: agent id to get policies from
    :param q: Defines query to filter in DB.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
    :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
    :param filters: Defines field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}

    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    if select is None:
        select = {'fields': list(fields_translation_ca.keys())}

    db_query = WazuhDBQueryPM(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                              select=select, count=True, get_data=True, query=q, filters=filters)
    return db_query.run()


def get_ca_checks(policy_id, agent_id=None, q="", offset=0, limit=common.database_limit,
                  sort=None, search=None, select=None, filters={}):
    """
    Gets a list of checks analized for a policy
    :param policy_id: policy id to get the checks from
    :param agent_id: agent id to get the policies from
    :param q: Defines query to filter in DB.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
    :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
    :param filters: Defines field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}

    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    fields_translation = {**fields_translation_ca_check,
                          **fields_translation_ca_check_compliance}
    if select is None:
        select = {'fields': (list(fields_translation_ca_check.keys()) +
                             list(fields_translation_ca_check_compliance.keys()))
                  }
    else:
        if 'policy_id' not in select['fields']:
            select['fields'].append('policy_id')

    db_query = WazuhDBQueryPM(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                              select=select, count=True, get_data=True,
                              query=f"policy_id='{policy_id}'" if q == "" else f"policy_id='{policy_id}';{q}",
                              filters=filters, default_query=default_query_ca_check, default_sort_field='policy_id',
                              fields=fields_translation, count_field='id')

    result_dict = db_query.run()

    if 'items' in result_dict:
        checks = result_dict['items']
    else:
        raise WazuhException(2007)

    groups = groupby(checks, key=lambda row: row['id'])
    result = []
    # Rearrange check and compliance fields
    for _, group in groups:
        group_list = list(group)
        check_dict = {k: v for k, v in group_list[0].items()
                      if k in set([col.replace('`', '') for col in fields_translation_ca_check.values()])
                      }
        check_dict['compliance'] = [{k: v for k, v in elem.items()
                                     if k in fields_translation_ca_check_compliance.values()}
                                    for elem in group_list
                                    ]
        result.append(check_dict)

    return {'totalItems': result_dict['totalItems'], 'items': result}
