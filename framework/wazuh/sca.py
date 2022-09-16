#!/usr/bin/env python

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core import common
from wazuh.core.agent import get_agents_info
from wazuh.core.exception import WazuhResourceNotFound
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.sca import WazuhDBQuerySCA, WazuhDBQuerySCACheckRelational, \
    WazuhDBQuerySCACheck
from wazuh.rbac.decorators import expose_resources


@expose_resources(actions=["sca:read"], resources=['agent:id:{agent_list}'])
def get_sca_list(agent_list=None, q="", offset=0, limit=common.DATABASE_LIMIT, sort=None, search=None, filters=None):
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

            with WazuhDBQuerySCA(agent_id=agent_list[0], offset=offset, limit=limit, sort=sort, search=search,
                                 count=True, get_data=True, query=q, filters=filters) as db_query:
                data = db_query.run()

            result.affected_items.extend(data['items'])
            result.total_affected_items = data['totalItems']
        else:
            result.add_failed_item(id_=agent_list[0], error=WazuhResourceNotFound(1701))

    return result


@expose_resources(actions=["sca:read"], resources=['agent:id:{agent_list}'])
def get_sca_checks(policy_id=None, agent_list=None, q="", offset=0, limit=common.DATABASE_LIMIT, sort=None, search=None,
                   filters=None):
    """Get a list of checks analyzed for a policy

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
        if agent_list[0] in get_agents_info():

            with WazuhDBQuerySCACheck(agent_id=agent_list[0], offset=offset, limit=limit, sort=sort, filters=filters,
                                      search=search, query=q, policy_id=policy_id) as sca_check_query:
                sca_check_data = sca_check_query.run()

            id_check_list = [check['id'] for check in sca_check_data['items']]
            flag_id_check_list_changed = False

            # Apply search on compliance and rules
            if search is not None:
                with WazuhDBQuerySCACheckRelational(agent_id=agent_list[0], table="sca_check_compliance",
                                                    search=search) as sca_check_compliance_query:
                    compliance_items_search = sca_check_compliance_query.run()['items']

                with WazuhDBQuerySCACheckRelational(agent_id=agent_list[0], table="sca_check_rules",
                                                    search=search) as sca_check_rules_query:
                    rules_items_search = sca_check_rules_query.run()['items']

                for compliance in compliance_items_search:
                    if compliance['id_check'] not in id_check_list:
                        flag_id_check_list_changed = True
                        id_check_list.append(compliance['id_check'])
                for rule in rules_items_search:
                    if rule['id_check'] not in id_check_list:
                        flag_id_check_list_changed = True
                        id_check_list.append(rule['id_check'])

            # Get SCA checks if id_check_list was updated (here we do not use filters, query or search)
            if flag_id_check_list_changed:
                with WazuhDBQuerySCACheck(agent_id=agent_list[0], offset=offset, limit=limit, sort=sort,
                                          policy_id=policy_id, filters=None, search=None,
                                          query=",".join(
                                              f"id={id_check}" for id_check in id_check_list)) as sca_check_query:
                    sca_check_data = sca_check_query.run()

            # Get compliance and rules
            if id_check_list:
                with WazuhDBQuerySCACheckRelational(agent_id=agent_list[0], table="sca_check_compliance",
                                                    id_check_list=id_check_list) as sca_check_compliance_query:
                    sca_check_compliance_items = sca_check_compliance_query.run()['items']

                with WazuhDBQuerySCACheckRelational(agent_id=agent_list[0], table="sca_check_rules",
                                                    id_check_list=id_check_list) as sca_check_rules_query:
                    sca_check_rules_items = sca_check_rules_query.run()['items']

                # Add compliance and rules to SCA checks data
                id_check_rules_compliance = {id_check: {'compliance': [], 'rules': []} for id_check in id_check_list}
                for compliance in sca_check_compliance_items:
                    id_check_rules_compliance[compliance['id_check']]['compliance'].append(
                        {k: v for k, v in compliance.items() if k != 'id_check'})
                for rule in sca_check_rules_items:
                    id_check_rules_compliance[rule['id_check']]['rules'].append(
                        {k: v for k, v in rule.items() if k != 'id_check'})

                for sca_check in sca_check_data['items']:
                    sca_check['compliance'] = id_check_rules_compliance[sca_check['id']]['compliance']
                    sca_check['rules'] = id_check_rules_compliance[sca_check['id']]['rules']

            result.affected_items.extend(sca_check_data['items'])
            result.total_affected_items = sca_check_data['totalItems']

        else:
            result.add_failed_item(id_=agent_list[0], error=WazuhResourceNotFound(1701))
            result.total_affected_items = 0

    return result
