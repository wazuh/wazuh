#!/usr/bin/env python

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core import common
from wazuh.core.agent import get_agents_info
from wazuh.core.exception import WazuhResourceNotFound
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.sca import (
    WazuhDBQueryDistinctSCACheck, WazuhDBQuerySCA, WazuhDBQuerySCACheck, WazuhDBQuerySCACheckIDs,
    WazuhDBQuerySCACheckRelational, SCA_CHECK_COMPLIANCE_DB_FIELDS, SCA_CHECK_RULES_DB_FIELDS, SCA_CHECK_DB_FIELDS)
from wazuh.rbac.decorators import expose_resources


@expose_resources(actions=["sca:read"], resources=['agent:id:{agent_list}'])
def get_sca_list(agent_list: list = None, q: str = "", offset: int = 0, limit: int = common.DATABASE_LIMIT,
                 sort: dict = None, search: dict = None, select: list = None, distinct: bool = False,
                 filters: dict = None) -> AffectedItemsWazuhResult:
    """Get a list of policies analyzed in the configuration assessment for a given agent.

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
    sort : dict
        Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    search : dict
        Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
    select : list
        Select fields to return. Format: ["field1","field2"].
    distinct : bool
        Look for distinct values.
    filters : dict
        Define field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    result = AffectedItemsWazuhResult(all_msg='All selected SCA information was returned',
                                      some_msg='Some SCA information was not returned',
                                      none_msg='No SCA information was returned'
                                      )

    if len(agent_list) != 0:
        if agent_list[0] in get_agents_info():

            with WazuhDBQuerySCA(agent_id=agent_list[0], offset=offset, limit=limit, sort=sort, search=search,
                                 select=select, count=True, get_data=True, query=q, filters=filters,
                                 distinct=distinct) as db_query:
                data = db_query.run()

            result.affected_items.extend(data['items'])
            result.total_affected_items = data['totalItems']
        else:
            result.add_failed_item(id_=agent_list[0], error=WazuhResourceNotFound(1701))

    return result


@expose_resources(actions=["sca:read"], resources=['agent:id:{agent_list}'])
def get_sca_checks(policy_id: str = None, agent_list: list = None, q: str = "", offset: int = 0,
                   limit: int = common.DATABASE_LIMIT, sort: dict = None, search: dict = None, select: list = None,
                   filters: dict = None, distinct: bool = False) -> AffectedItemsWazuhResult:
    """Get a list of checks analyzed for a policy.

    Parameters
    ----------
    policy_id : str
        Policy id to get the checks from.
    agent_list : list
        Agent id to get the policies from.
    q : str
        Defines query to filter in DB.
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    sort : dict
        Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    search : dict
        Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
    select : list
        Select which fields to return.
    filters : dict
        Define field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}
    distinct : bool
        Look for distinct values.

    Raises
    ------
    WazuhInternalError(2007)
        If there was an error retrieving data from Wazuh DB.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    result = AffectedItemsWazuhResult(all_msg='All selected SCA/policy information was returned',
                                      some_msg='Some SCA/policy information was not returned',
                                      none_msg='No SCA/policy information was returned'
                                      )
    if len(agent_list) != 0:
        if agent_list[0] in get_agents_info():

            # Workaround for distinct=False
            if not distinct:
                # Get SCA checks IDs from the checks, rules and compliance tables
                # The query includes the `filters`, `q`, `search`, `limit`, `offset` and `sort` parameters
                with WazuhDBQuerySCACheckIDs(agent_id=agent_list[0], offset=offset, limit=limit, filters=filters,
                                             search=search, query=q, policy_id=policy_id, sort=sort) as sca_check_query:
                    sca_check_data = sca_check_query.run()
                    result.total_affected_items = sca_check_data['totalItems']

                # Create SCA checks IDs list from the query response
                id_check_list = [check['id'] for check in sca_check_data['items']]

                if id_check_list:
                    # Get SCA checks items from the checks table with the SCA checks IDs list
                    # The query includes the `sort` and `select` parameters
                    with WazuhDBQuerySCACheck(
                            agent_id=agent_list[0],
                            select=select if not select else [s for s in select if
                                                              s not in SCA_CHECK_RULES_DB_FIELDS.keys() and s not in
                                                              SCA_CHECK_COMPLIANCE_DB_FIELDS.keys()],
                            sort=sort, sca_checks_ids=id_check_list) as sca_check_query:
                        sca_check_data = sca_check_query.run()

                    # Get compliance if all fields selected (not select), or if a compliance field is in select
                    sca_check_compliance_items = []
                    select_compliance = [s for s in select if s not in SCA_CHECK_RULES_DB_FIELDS.keys() and s not in
                                         SCA_CHECK_DB_FIELDS.keys()] if select else None
                    if not select or select_compliance:
                        with WazuhDBQuerySCACheckRelational(
                                agent_id=agent_list[0], table="sca_check_compliance", id_check_list=id_check_list,
                                select=select if not select
                                else select_compliance + ['id_check']) as sca_check_compliance_query:
                            sca_check_compliance_items = sca_check_compliance_query.run()['items']

                    # Get rules if all fields selected (not select), or if a rules field is in select
                    sca_check_rules_items = []
                    select_rules = [s for s in select if s not in SCA_CHECK_COMPLIANCE_DB_FIELDS.keys() and s not in
                                    SCA_CHECK_DB_FIELDS.keys()] if select else None
                    if not select or select_rules:
                        with WazuhDBQuerySCACheckRelational(
                                agent_id=agent_list[0], table="sca_check_rules", id_check_list=id_check_list,
                                select=select if not select
                                else select_rules + ['id_check']) as sca_check_rules_query:
                            sca_check_rules_items = sca_check_rules_query.run()['items']

                    # Add compliance and rules to SCA checks data
                    id_check_rules_compliance = {id_check: {'compliance': [], 'rules': []} for id_check in
                                                 id_check_list}
                    for compliance in sca_check_compliance_items:
                        id_check_rules_compliance[compliance['id_check']]['compliance'].append(
                            {k.split('.')[1]: v for k, v in compliance.items() if k != 'id_check'})
                    for rule in sca_check_rules_items:
                        id_check_rules_compliance[rule['id_check']]['rules'].append(
                            {k.split('.')[1]: v for k, v in rule.items() if k != 'id_check'})

                    if sca_check_rules_items and sca_check_compliance_items:
                        for sca_check in sca_check_data['items']:
                            sca_check['compliance'] = id_check_rules_compliance[sca_check['id']]['compliance']
                            sca_check['rules'] = id_check_rules_compliance[sca_check['id']]['rules']
                    elif sca_check_rules_items:
                        for sca_check in sca_check_data['items']:
                            sca_check['rules'] = id_check_rules_compliance[sca_check['id']]['rules']
                    elif sca_check_compliance_items:
                        for sca_check in sca_check_data['items']:
                            sca_check['compliance'] = id_check_rules_compliance[sca_check['id']]['compliance']

                result.affected_items.extend(sca_check_data['items'])

            # Workaround for distinct=True
            else:
                # Get SCA checks fields distinct
                with WazuhDBQueryDistinctSCACheck(agent_id=agent_list[0], offset=offset, limit=limit, filters=filters,
                                                  search=search, query=q, policy_id=policy_id, sort=sort,
                                                  select=select) as sca_check_query:
                    sca_check_data = sca_check_query.run()

                result.total_affected_items = sca_check_data['totalItems']
                result.affected_items.extend(sca_check_data['items'])

        else:
            result.add_failed_item(id_=agent_list[0], error=WazuhResourceNotFound(1701))
            result.total_affected_items = 0

    return result
