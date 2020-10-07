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
from wazuh.rbac.decorators import expose_resources


@expose_resources(actions=["sca:read"], resources=['agent:id:{agent_list}'])
def get_sca_list(agent_list=None, q="", offset=0, limit=common.database_limit, sort=None, search=None, select=None,
                 filters=None):
    """ Get a list of policies analyzed in the configuration assessment for a given agent

    :param agent_list: agent id to get policies from
    :param q: Defines query to filter in DB.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
    :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
    :param filters: Define field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}
    :return: AffectedItemsWazuhResult
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

    :param policy_id: policy id to get the checks from
    :param agent_list: agent id to get the policies from
    :param q: Defines query to filter in DB.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
    :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
    :param filters: Define field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}
    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(all_msg='All selected sca/policy information was returned',
                                      some_msg='Some sca/policy information was not returned',
                                      none_msg='No sca/policy information was returned'
                                      )
    if len(agent_list) != 0:
        if agent_list[0] in get_agents_info():
            fields_translation = {**fields_translation_sca_check,
                                  **fields_translation_sca_check_compliance,
                                  **fields_translation_sca_check_rule}

            full_select = (list(fields_translation_sca_check.keys()) +
                           list(fields_translation_sca_check_compliance.keys()) +
                           list(fields_translation_sca_check_rule.keys())
                           )

            db_query = WazuhDBQuerySCA(agent_id=agent_list[0], offset=offset, limit=limit, sort=sort, search=search,
                                       select=full_select, count=True, get_data=True,
                                       query=f"policy_id={policy_id}" if q == "" else f"policy_id={policy_id};{q}",
                                       filters=filters, default_query=default_query_sca_check,
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
                                                   for x in set((map(itemgetter(*field_translations.keys()),
                                                                     group_list)))]

                result.affected_items.append(check_dict)
            result.total_affected_items = result_dict['totalItems']
        else:
            result.add_failed_item(id_=agent_list[0], error=WazuhResourceNotFound(1701))
            result.total_affected_items = 0

    return result
