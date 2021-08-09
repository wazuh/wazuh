# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from glob import glob
from typing import Union

from wazuh.core import common
from wazuh.core.agent import Agent, get_agents_info, get_rbac_filters, WazuhDBQueryAgents
from wazuh.core.database import Connection
from wazuh.core.exception import WazuhInternalError, WazuhError, WazuhResourceNotFound
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.syscheck import WazuhDBQuerySyscheck, syscheck_delete_agent
from wazuh.core.utils import WazuhVersion
from wazuh.core.wazuh_queue import WazuhQueue
from wazuh.rbac.decorators import expose_resources
from wazuh.core.wdb import WazuhDBConnection


@expose_resources(actions=["syscheck:run"], resources=["agent:id:{agent_list}"])
def run(agent_list: Union[str, None] = None) -> AffectedItemsWazuhResult:
    """Run a syscheck scan in the specified agents.

    Parameters
    ----------
    agent_list : Union[str, None]
        List of the agents IDs to run the scan for.

    Returns
    -------
    result : AffectedItemsWazuhResult
        Confirmation/Error message.
    """
    result = AffectedItemsWazuhResult(all_msg='Syscheck scan was restarted on returned agents',
                                      some_msg='Syscheck scan was not restarted on some agents',
                                      none_msg='No syscheck scan was restarted')

    system_agents = get_agents_info()
    rbac_filters = get_rbac_filters(system_resources=system_agents, permitted_resources=agent_list)
    agent_list = set(agent_list)
    not_found_agents = agent_list - system_agents

    # Add non existent agents to failed_items
    [result.add_failed_item(id_=agent, error=WazuhResourceNotFound(1701)) for agent in not_found_agents]

    # Add non eligible agents to failed_items
    with WazuhDBQueryAgents(limit=None, select=["id", "status"], query='status!=active', **rbac_filters) as db_query:
        non_eligible_agents = db_query.run()['items']

    [result.add_failed_item(
        id_=agent['id'],
        error=WazuhError(1707)) for agent in non_eligible_agents]

    wq = WazuhQueue(common.ARQUEUE)
    eligible_agents = agent_list - not_found_agents - {d['id'] for d in non_eligible_agents}
    for agent_id in eligible_agents:
        try:
            wq.send_msg_to_agent(WazuhQueue.HC_SK_RESTART, agent_id)
            result.affected_items.append(agent_id)
        except WazuhError as e:
            result.add_failed_item(id_=agent_id, error=e)
    wq.close()
    result.affected_items = sorted(result.affected_items, key=int)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=["syscheck:clear"], resources=["agent:id:{agent_list}"])
def clear(agent_list=None):
    """Clear the syscheck database of the specified agents.

    Parameters
    ----------
    agent_list : str
        Agent ID.

    Returns
    -------
    result : AffectedItemsWazuhResult
        Confirmation/Error message.
    """
    result = AffectedItemsWazuhResult(all_msg='Syscheck database was cleared on returned agents',
                                      some_msg='Syscheck database was not cleared on some agents',
                                      none_msg="No syscheck database was cleared")

    system_agents = get_agents_info()
    wdb_conn = None
    for agent in agent_list:
        if agent not in system_agents:
            result.add_failed_item(id_=agent, error=WazuhResourceNotFound(1701))
        else:
            try:
                if wdb_conn is None:
                    wdb_conn = WazuhDBConnection()
                syscheck_delete_agent(agent, wdb_conn)
                result.affected_items.append(agent)
            except WazuhError as e:
                result.add_failed_item(id_=agent, error=e)

    if wdb_conn is not None:
        wdb_conn.close()
    result.affected_items.sort(key=int)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=["syscheck:read"], resources=["agent:id:{agent_list}"])
def last_scan(agent_list):
    """Get the last scan of an agent.

    Parameters
    ----------
    agent_list : str
        Agent ID.

    Returns
    -------
    result : AffectedItemsWazuhResult
        Confirmation/Error message.
    """
    my_agent = Agent(agent_list[0])
    result = AffectedItemsWazuhResult(all_msg='Last syscheck scan of the agent was returned',
                                      none_msg='No last scan information was returned')
    # If agent status is never_connected, a KeyError happens
    try:
        agent_version = my_agent.get_basic_information(select=['version'])['version']
    except KeyError:
        # If the agent is never_connected, it won't have either version (key error) or last scan information.
        result.affected_items.append({'start': None, 'end': None})
        result.total_affected_items += 1

        return result

    if WazuhVersion(agent_version) < WazuhVersion('Wazuh v3.7.0'):
        db_agent = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_list[0]))
        if not db_agent:
            raise WazuhInternalError(1600, extra_message=agent_list[0])
        else:
            db_agent = db_agent[0]
        conn = Connection(db_agent)

        data = {}
        # end time
        query = "SELECT max(date_last) FROM pm_event WHERE log = 'Ending rootcheck scan.'"
        conn.execute(query)
        for t in conn:
            data['end'] = t['max(date_last)'] if t['max(date_last)'] is not None else "ND"

        # start time
        query = "SELECT max(date_last) FROM pm_event WHERE log = 'Starting rootcheck scan.'"
        conn.execute(query)
        for t in conn:
            data['start'] = t['max(date_last)'] if t['max(date_last)'] is not None else "ND"

        result.affected_items.append(data)
    else:
        with WazuhDBQuerySyscheck(agent_id=agent_list[0], query='module=fim', offset=0, sort=None,
                                  search=None, limit=common.database_limit, select={'end', 'start'},
                                  fields={'end': 'end_scan', 'start': 'start_scan', 'module': 'module'},
                                  table='scan_info', default_sort_field='start_scan') as db_query:
            fim_scan_info = db_query.run()['items'][0]

        end = None if not fim_scan_info['end'] else fim_scan_info['end']
        start = None if not fim_scan_info['start'] else fim_scan_info['start']
        # If start is None or the scan is running, end will be None.
        result.affected_items.append(
            {'start': start, 'end': None if start is None else None if end is None or end < start else end})
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=["syscheck:read"], resources=["agent:id:{agent_list}"])
def files(agent_list=None, offset=0, limit=common.database_limit, sort=None, search=None, select=None, filters=None,
          q='', nested=True, summary=False, distinct=False):
    """Return a list of files from the syscheck database of the specified agents.

    Parameters
    ----------
    agent_list : str
        Agent ID.
    filters : dict
        Fields to filter by.
    summary : bool
        Returns a summary grouping by filename.
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    sort : str
        Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    search : str
        Looks for items with the specified string.
    select : list[str]
        Select fields to return. Format: ["field1","field2"].
    q : str
        Query to filter by.
    nested : bool
        Specify whether there are nested fields or not.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    result : AffectedItemsWazuhResult
        Confirmation/Error message.
    """
    if filters is None:
        filters = {}
    parameters = {"date": "date", "arch": "arch", "value.type": "value_type", "value.name": "value_name",
                  "mtime": "mtime", "file": "file", "size": "size", "perm": "perm",
                  "uname": "uname", "gname": "gname", "md5": "md5", "sha1": "sha1", "sha256": "sha256",
                  "inode": "inode", "gid": "gid", "uid": "uid", "type": "type", "changes": "changes",
                  "attributes": "attributes"}
    summary_parameters = {"date": "date", "mtime": "mtime", "file": "file"}
    result = AffectedItemsWazuhResult(all_msg='FIM findings of the agent were returned',
                                      none_msg='No FIM information was returned')

    if 'hash' in filters:
        q = f'(md5={filters["hash"]},sha1={filters["hash"]},sha256={filters["hash"]})' + ('' if not q else ';' + q)
        del filters['hash']

    with WazuhDBQuerySyscheck(agent_id=agent_list[0], offset=offset, limit=limit, sort=sort, search=search,
                              filters=filters, nested=nested, query=q, select=select, table='fim_entry',
                              distinct=distinct, fields=summary_parameters if summary else parameters,
                              min_select_fields={'file'}) as db_query:
        db_query = db_query.run()

    result.affected_items = db_query['items']
    result.total_affected_items = db_query['totalItems']

    return result
