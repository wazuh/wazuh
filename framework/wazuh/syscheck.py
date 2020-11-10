# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from glob import glob

from wazuh.core import common
from wazuh.core.agent import Agent, get_agents_info
from wazuh.core.database import Connection
from wazuh.core.exception import WazuhInternalError, WazuhError, WazuhResourceNotFound
from wazuh.core.ossec_queue import OssecQueue
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.syscheck import WazuhDBQuerySyscheck
from wazuh.core.utils import WazuhVersion
from wazuh.core.wdb import WazuhDBConnection
from wazuh.rbac.decorators import expose_resources


@expose_resources(actions=["syscheck:run"], resources=["agent:id:{agent_list}"])
def run(agent_list=None):
    """Run syscheck scan.
    :param agent_list: Run syscheck in the agent.
    :return: AffectedItemsWazuhResult.
    """
    result = AffectedItemsWazuhResult(all_msg='Syscheck scan was restarted on returned agents',
                                      some_msg='Syscheck scan was not restarted on some agents',
                                      none_msg='No syscheck scan was restarted')
    for agent_id in agent_list:
        try:
            agent_info = Agent(agent_id).get_basic_information()
            agent_status = agent_info.get('status', 'N/A')
            if agent_status.lower() != 'active':
                result.add_failed_item(
                    id_=agent_id, error=WazuhError(1601, extra_message='Status - {}'.format(agent_status)))
            else:
                oq = OssecQueue(common.ARQUEUE)
                oq.send_msg_to_agent(OssecQueue.HC_SK_RESTART, agent_id)
                result.affected_items.append(agent_id)
                oq.close()
        except WazuhError as e:
            result.add_failed_item(id_=agent_id, error=e)
    result.affected_items = sorted(result.affected_items, key=int)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=["syscheck:clear"], resources=["agent:id:{agent_list}"])
def clear(agent_list=None):
    """Clear the syscheck database for a list of agents.

    :param agent_list: List of agent ids
    :return: AffectedItemsWazuhResult.
    """
    result = AffectedItemsWazuhResult(all_msg='Syscheck database was cleared on returned agents',
                                      some_msg='Syscheck database was not cleared on some agents',
                                      none_msg="No syscheck database was cleared")
    wdb_conn = WazuhDBConnection()
    for agent in agent_list:
        if agent not in get_agents_info():
            result.add_failed_item(id_=agent, error=WazuhResourceNotFound(1701))
        else:
            try:
                wdb_conn.execute("agent {} sql delete from fim_entry".format(agent), delete=True)
                # Update key fields which contains keys to value 000
                wdb_conn.execute("agent {} sql update metadata set value = '000' "
                                 "where key like 'fim_db%'".format(agent), update=True)
                wdb_conn.execute("agent {} sql update metadata set value = '000' "
                                 "where key = 'syscheck-db-completed'".format(agent), update=True)
                result.affected_items.append(agent)
            except WazuhError as e:
                result.add_failed_item(id_=agent, error=e)

    result.affected_items.sort(key=int)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=["syscheck:read"], resources=["agent:id:{agent_list}"])
def last_scan(agent_list):
    """Gets the last scan of the agent.

    :param agent_list: Agent ID.
    :return: AffectedItemsWazuhResult.
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
        fim_scan_info = WazuhDBQuerySyscheck(agent_id=agent_list[0], query='module=fim', offset=0, sort=None,
                                             search=None, limit=common.database_limit, select={'end', 'start'},
                                             fields={'end': 'end_scan', 'start': 'start_scan', 'module': 'module'},
                                             table='scan_info', default_sort_field='start_scan').run()['items'][0]
        end = None if not fim_scan_info['end'] else fim_scan_info['end']
        start = None if not fim_scan_info['start'] else fim_scan_info['start']
        # If start is None or the scan is running, end will be None.
        result.affected_items.append(
            {'start': start, 'end': None if start is None else None if end is None or end < start else end})
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=["syscheck:read"], resources=["agent:id:{agent_list}"])
def files(agent_list=None, offset=0, limit=common.database_limit, sort=None, search=None, select=None, filters=None,
          q='', summary=False, distinct=False):
    """Return a list of files from the database that match the filters

    :param agent_list: Agent ID.
    :param filters: Fields to filter by
    :param summary: Returns a summary grouping by filename.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :param select: Select fields to return. Format: ["field1","field2"].
    :param q: Query to filter by
    :param distinct: Look for distinct values
    :return: AffectedItemsWazuhResult.
    """
    if filters is None:
        filters = {}
    parameters = {"date": "date", "mtime": "mtime", "file": "file", "size": "size", "perm": "perm", "uname": "uname",
                  "gname": "gname", "md5": "md5", "sha1": "sha1", "sha256": "sha256", "inode": "inode", "gid": "gid",
                  "uid": "uid", "type": "type", "changes": "changes", "attributes": "attributes"}
    summary_parameters = {"date": "date", "mtime": "mtime", "file": "file"}
    result = AffectedItemsWazuhResult(all_msg='FIM findings of the agent were returned',
                                      none_msg='No FIM information was returned')

    if 'hash' in filters:
        q = f'(md5={filters["hash"]},sha1={filters["hash"]},sha256={filters["hash"]})' + ('' if not q else ';' + q)
        del filters['hash']

    db_query = WazuhDBQuerySyscheck(agent_id=agent_list[0], offset=offset, limit=limit, sort=sort, search=search,
                                    filters=filters, query=q, select=select, table='fim_entry', distinct=distinct,
                                    fields=summary_parameters if summary else parameters)

    db_query = db_query.run()

    result.affected_items = db_query['items']
    result.total_affected_items = db_query['totalItems']

    return result
