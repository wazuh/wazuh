#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from itertools import groupby
from operator import itemgetter

from wazuh.core import common
from wazuh.core.agent import get_agents_info
from wazuh.core.exception import WazuhInternalError, WazuhResourceNotFound
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.sca import WazuhDBQuerySCA, fields_translation_sca, fields_translation_sca_check, \
    fields_translation_sca_check_compliance, fields_translation_sca_check_rule, default_query_sca_check
from wazuh.core.utils import process_array
from wazuh.rbac.decorators import expose_resources


@expose_resources(actions=["sca:read"], resources=['agent:id:{agent_list}'])
def get_sca_list(agent_list=None, q="", offset=0, limit=common.database_limit, sort=None, search=None, select=None,
                 filters=None):
    """ Get a list of policies analyzed in the configuration assessment for a given agent

    Parameters
    ----------
    agent_list : list
        Agent ids to get policies from.
    q : str
        Defines query to filter in DB.
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    sort : str
        Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    search : str
        Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
    select : str
        Select fields to return. Format: {"fields":["field1","field2"]}.
    filters : str
        Define field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}

    Returns
    -------
    AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(all_msg='All selected sca information was returned',
                                      some_msg='Some sca information was not returned',
                                      none_msg='No sca information was returned'
                                      )

    if len(agent_list) != 0:
        if agent_list[0] in get_agents_info():
            select = list(fields_translation_sca.keys()) if select is None else select

            db_query = WazuhDBQuerySCA(agent_id=agent_list[0], offset=offset, limit=limit, sort=sort, search=search,
                                       select=select, count=True, get_data=True, query=q, filters=filters)
            data = db_query.run()
            result.affected_items.extend(data['items'])
            result.total_affected_items = data['totalItems']
        else:
            result.add_failed_item(id_=agent_list[0], error=WazuhResourceNotFound(1701))

    return result


@expose_resources(actions=["sca:read"], resources=['agent:id:{agent_list}'])
def get_sca_checks(policy_id=None, agent_list=None, q="", offset=0, limit=common.database_limit, sort=None, search=None,
                   select=None, filters=None):
    """ Get a list of checks analyzed for a policy

    Parameters
    ----------
    policy_id : str
        Policy id to get the checks from.
    agent_list : list
        Agent id to get the policies from
    q : str
        Defines query to filter in DB.
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    sort : str
        Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    search : str
        Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
    select : str
        Select fields to return. Format: {"fields":["field1","field2"]}.
    filters : str
        Define field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}

    Returns
    -------
    AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(all_msg='All selected sca/policy information was returned',
                                      some_msg='Some sca/policy information was not returned',
                                      none_msg='No sca/policy information was returned'
                                      )
    if len(agent_list) != 0:
        sca_checks = list()
        if agent_list[0] in get_agents_info():
            fields_translation = {**fields_translation_sca_check,
                                  **fields_translation_sca_check_compliance,
                                  **fields_translation_sca_check_rule}

            full_select = (list(fields_translation_sca_check.keys()) +
                           list(fields_translation_sca_check_compliance.keys()) +
                           list(fields_translation_sca_check_rule.keys())
                           )

            # Workaround for too long sca_checks results until the chunk algorithm is implemented (1/2)
            db_query = WazuhDBQuerySCA(agent_id=agent_list[0], offset=0, limit=None, sort=None, filters=filters,
                                       search=None, select=full_select, count=True, get_data=True,
                                       query=f"policy_id={policy_id}",
                                       default_query=default_query_sca_check,
                                       default_sort_field='policy_id', fields=fields_translation, count_field='id')
            result_dict = db_query.run()

            if 'items' in result_dict:
                checks = result_dict['items']
            else:
                raise WazuhInternalError(2007)

            groups = groupby(checks, key=itemgetter('id'))
            select_fields = full_select if select is None else select
            select_fields = set([field if field != 'compliance' else 'compliance'
                                 for field in select_fields if field in fields_translation_sca_check])
            # Rearrange check and compliance fields

            for _, group in groups:
                group_list = list(group)
                check_dict = {k: v for k, v in group_list[0].items()
                              if k in select_fields
                              }

                for extra_field, field_translations in [('compliance', fields_translation_sca_check_compliance),
                                                        ('rules', fields_translation_sca_check_rule)]:
                    if (select is None or extra_field in select) \
                            and set(field_translations.keys()) & group_list[0].keys():
                        check_dict[extra_field] = [dict(zip(field_translations.values(), x))
                                                   for x in sorted(set(map(itemgetter(*field_translations.keys()),
                                                                           group_list)))]

                sca_checks.append(check_dict)
        else:
            result.add_failed_item(id_=agent_list[0], error=WazuhResourceNotFound(1701))
            result.total_affected_items = 0

        # Workaround for too long sca_checks results until the chunk algorithm is implemented (2/2)
        data = process_array(sca_checks,
                             search_text=search['value'] if search else None,
                             complementary_search=search['negation'] if search else False,
                             sort_by=sort['fields'] if sort else ['policy_id'],
                             sort_ascending=False if sort and sort['order'] == 'desc' else True,
                             offset=offset,
                             limit=limit,
                             q=q)

        result.affected_items = data['items']
        result.total_affected_items = data['totalItems']

    return result
