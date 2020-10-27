# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.core.agent import get_agents_info
from wazuh.core.exception import WazuhError, WazuhResourceNotFound
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.rootcheck import WazuhDBQueryRootcheck, last_scan
from wazuh.core.wdb import WazuhDBConnection
from wazuh.rbac.decorators import expose_resources


@expose_resources(actions=["rootcheck:clear"], resources=["agent:id:{agent_list}"])
def clear(agent_list=None):
    """Clear the rootcheck database for a list of agents.

    :param agent_list: List of agent ids
    :return: AffectedItemsWazuhResult.
    """
    result = AffectedItemsWazuhResult(all_msg='Rootcheck database was cleared on returned agents',
                                      some_msg='Rootcheck database was not cleared on some agents',
                                      none_msg="No rootcheck database was cleared")

    wdb_conn = WazuhDBConnection()
    for agent_id in agent_list:
        if agent_id not in get_agents_info():
            result.add_failed_item(id_=agent_id, error=WazuhResourceNotFound(1701))
        else:
            try:
                wdb_conn.execute(f"agent {agent_id} rootcheck delete", delete=True)
                result.affected_items.append(agent_id)
            except WazuhError as e:
                result.add_failed_item(id_=agent_id, error=e)

    result.affected_items.sort(key=int)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=["rootcheck:read"], resources=["agent:id:{agent_list}"])
def get_last_scan(agent_list):
    """Gets the last rootcheck scan of the agent.

    :param agent_list: Agent ID to get the last scan date from
    :return: WazuhResult
    """
    result = AffectedItemsWazuhResult(all_msg='Last rootcheck scan of the agent was returned',
                                      none_msg='No last scan information was returned')

    result.affected_items.append(last_scan(agent_list[0]))
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=["rootcheck:read"], resources=["agent:id:{agent_list}"])
def get_rootcheck_agent(agent_list=None, offset=0, limit=common.database_limit, sort=None, search=None, select=None,
                        filters=None, q='', distinct=None):
    """Returns a list of events from the rootcheck database.

    :param agent_id: Agent ID.
    :param filters: Fields to filter by.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order
    :param select: Selects which fields to return.
    :param search: Looks for items with the specified string.
    :param q: Defines query to filter in DB.
    :param distinct: Look for distinct values
    :return: AffectedItemsWazuhResult
    """
    if filters is None:
        filters = {}
    result = AffectedItemsWazuhResult(all_msg='All selected rootcheck information was returned',
                                      some_msg='Some rootcheck information was not returned',
                                      none_msg='No rootcheck information was returned'
                                      )

    db_query = WazuhDBQueryRootcheck(agent_id=agent_list[0], offset=offset, limit=limit, sort=sort, search=search,
                                     select=select, count=True, get_data=True, query=q, filters=filters,
                                     distinct=distinct)
    data = db_query.run()
    result.affected_items.extend(data['items'])
    result.total_affected_items = data['totalItems']

    return result
