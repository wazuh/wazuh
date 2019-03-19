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
fields_translation_sca = {'policy_id': 'policy_id',
                          'name': 'name',
                          'description': 'description',
                          'references': '`references`',
                          'pass': 'pass',
                          'fail': 'fail',
                          'score': 'score',
                          'end_scan': "strftime('%Y-%m-%d %H:%M:%S', datetime(end_scan, 'unixepoch')) as end_scan",
                          'start_scan': "strftime('%Y-%m-%d %H:%M:%S', datetime(start_scan, 'unixepoch')) as start_scan"
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
                                'references': '`references`',
                                'result': 'result'}
fields_translation_sca_check_compliance = {'key': 'key',
                                           'value': 'value'}

default_query_sca = 'SELECT {0} FROM sca_policy sca INNER JOIN sca_scan_info si ON sca.id=si.policy_id'
default_query_sca_check = 'SELECT {0} FROM sca_check LEFT JOIN sca_check_compliance ON id=id_check'


class WazuhDBQuerySCA(WazuhDBQuery):

    def __init__(self, agent_id, offset, limit, sort, search, select, query, count, get_data,
                 default_query=default_query_sca, default_sort_field='policy_id', filters={},
                 fields=fields_translation_sca, count_field='policy_id'):
        self.default_query = default_query
        self.count_field = count_field

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='sca_policy', sort=sort,
                              search=search, select=select, fields=fields, default_sort_field=default_sort_field,
                              default_sort_order='DESC', filters=filters, query=query, count=count, get_data=get_data,
                              date_fields={'end_scan', 'start_scan'}, backend='wdb', db_path=None, agent_id=agent_id)

    def _default_query(self):
        return self.default_query

    def _default_count_query(self):
        return f"COUNT(DISTINCT {self.count_field})"


def get_sca_list(agent_id=None, q="", offset=0, limit=common.database_limit,
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
        select = {'fields': list(fields_translation_sca.keys())}

    db_query = WazuhDBQuerySCA(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                               select=select, count=True, get_data=True, query=q, filters=filters)
    return db_query.run()


def get_sca_checks(policy_id, agent_id=None, q="", offset=0, limit=common.database_limit,
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
    fields_translation = {**fields_translation_sca_check,
                          **fields_translation_sca_check_compliance}

    full_select = {'fields': (list(fields_translation_sca_check.keys()) +
                              list(fields_translation_sca_check_compliance.keys())
                              )
                   }

    db_query = WazuhDBQuerySCA(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                               select=full_select, count=True, get_data=True,
                               query=f"policy_id={policy_id}" if q == "" else f"policy_id={policy_id};{q}",
                               filters=filters, default_query=default_query_sca_check, default_sort_field='policy_id',
                               fields=fields_translation, count_field='id')

    result_dict = db_query.run()

    if 'items' in result_dict:
        checks = result_dict['items']
    else:
        raise WazuhException(2007)

    groups = groupby(checks, key=lambda row: row['id'])
    result = []
    select_fields = full_select['fields'] if select is None else select['fields']
    select_fields = set([fields_translation_sca_check[field] if field != 'compliance' else 'compliance'
                         for field in select_fields if field in fields_translation_sca_check])
    # Rearrange check and compliance fields
    for _, group in groups:
        group_list = list(group)
        check_dict = {k: v for k, v in group_list[0].items()
                      if k in set([col.replace('`', '') for col in select_fields])
                      }
        if select is None or 'compliance' in select['fields']:
            check_dict['compliance'] = list(filter(lambda x: x != {},
                                                   ({k: v for k, v in elem.items()
                                                     if k in fields_translation_sca_check_compliance.values()}
                                                    for elem in group_list
                                                    )
                                                   )
                                            )
        result.append(check_dict)

    return {'totalItems': result_dict['totalItems'], 'items': result}
