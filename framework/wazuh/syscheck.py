

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from glob import glob
from operator import itemgetter
from wazuh.exception import WazuhException, WazuhInternalError, WazuhError
from wazuh.agent import Agent
from wazuh.ossec_queue import OssecQueue
from wazuh import common, Connection
from datetime import datetime
from wazuh.wdb import WazuhDBConnection
from wazuh.utils import WazuhVersion


def run(agent_id=None, all_agents=False):
    """
    Runs rootcheck and syscheck.

    :param agent_id: Run rootcheck/syscheck in the agent.
    :param all_agents: Run rootcheck/syscheck in all agents.
    :return: Message.
    """

    if agent_id == "000" or all_agents:

        SYSCHECK_RESTART = "{0}/var/run/.syscheck_run".format(common.ossec_path)

        fp = open(SYSCHECK_RESTART, 'w')
        fp.write('{0}\n'.format(SYSCHECK_RESTART))
        fp.close()
        ret_msg = "Restarting Syscheck/Rootcheck locally"

        if all_agents:
            oq = OssecQueue(common.ARQUEUE)
            ret_msg = oq.send_msg_to_agent(OssecQueue.HC_SK_RESTART)
            oq.close()
    else:
        # Check if agent exists
        agent_info = Agent(agent_id).get_basic_information()
        if 'status' in agent_info:
            agent_status = agent_info['status']
        else:
            agent_status = "N/A"
        if agent_status.lower() != 'active':
            raise WazuhInternalError(1601, extra_message='{0} - {1}'.format(agent_id, agent_status))

        oq = OssecQueue(common.ARQUEUE)
        ret_msg = oq.send_msg_to_agent(OssecQueue.HC_SK_RESTART, agent_id)
        oq.close()

    return ret_msg


def clear(agent_id=None, all_agents=False):
    """
    Clears the database.

    :param agent_id: For an agent.
    :param all_agents: For all agents.
    :return: Message.
    """
    agents = [agent_id] if not all_agents else map(itemgetter('id'), Agent.get_agents_overview(select=['id'])['items'])

    wdb_conn = WazuhDBConnection()
    for agent in agents:
        Agent(agent).get_basic_information()  # check if the agent exists
        wdb_conn.execute("agent {} sql delete from fim_entry".format(agent), delete=True)
        # update key fields which contains keys to value 000
        wdb_conn.execute("agent {} sql update metadata set value = '000' where key like 'fim_db%'".format(agent), update=True)
        wdb_conn.execute("agent {} sql update metadata set value = '000' where key = 'syscheck-db-completed'".format(agent), update=True)

    return "Syscheck database deleted"


def last_scan(agent_id):
    """
    Gets the last scan of the agent.

    :param agent_id: Agent ID.
    :return: Dictionary: end, start.
    """
    my_agent = Agent(agent_id)
    # if agent status is never connected, a KeyError happens
    try:
        agent_version = my_agent.get_basic_information(select=['version'])['version']
    except KeyError:
        # if the agent is never connected, it won't have either version (key error) or last scan information.
        return {'start': None, 'end': None}

    if WazuhVersion(agent_version) < WazuhVersion('Wazuh v3.7.0'):
        db_agent = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_id))
        if not db_agent:
            raise WazuhInternalError(1600, extra_message=agent_id)
        else:
            db_agent = db_agent[0]
        conn = Connection(db_agent)
        # end time
        query = "SELECT date_last, log FROM pm_event WHERE log LIKE '% syscheck scan.'"
        conn.execute(query)

        return {'end' if log.startswith('End') else 'start': date_last for date_last, log in conn}
    else:
        fim_scan_info = my_agent._load_info_from_agent_db(table='scan_info', select={'end_scan', 'start_scan'},
                                                          filters={'module': 'fim'})[0]
        end = None if not fim_scan_info['end_scan'] else datetime.fromtimestamp(float(fim_scan_info['end_scan']))
        start = None if not fim_scan_info['start_scan'] else datetime.fromtimestamp(float(fim_scan_info['start_scan']))
        # if start is 'ND', end will be as well.
        return {'start': start, 'end': None if start is None else end}


def files(agent_id=None, summary=False, offset=0, limit=common.database_limit, sort=None, search=None, select=None, filters={}):
    """
    Return a list of files from the database that match the filters

    :param agent_id: Agent ID.
    :param filters: Fields to filter by
    :param summary: Returns a summary grouping by filename.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    parameters = {"date", "mtime", "file", "size", "perm", "uname", "gname", "md5", "sha1", "sha256", "inode", "gid",
                  "uid", "type", "attributes", "symbolic_path"}
    summary_parameters = {"date", "mtime", "file"}

    if sort is not None:
        for element in sort['fields']:
            if element not in parameters:
                raise WazuhError(1403, extra_message=', '.join(set(sort['fields']) - parameters),
                                 extra_remediation="Allowed fields are: {0}".format(', '.join(parameters)))

    if select is None:
        select = summary_parameters if summary else parameters
    else:
        select = set(select)
        if not select.issubset(parameters):
            raise WazuhError(1724,extra_message=', '.join(select - parameters),
                             extra_remediation="Allowed fields are: {0}".format(', '.join(parameters)))

    if 'hash' in filters:
        or_filters = {'md5': filters['hash'], 'sha1': filters['hash'], 'sha256': filters['hash']}
        del filters['hash']
    else:
        or_filters = {}

    items, totalItems = Agent(agent_id)._load_info_from_agent_db(table='fim_entry', select=select, offset=offset, limit=limit,
                                                        sort=sort, search=search, filters=filters, count=True,
                                                        or_filters=or_filters)
    for date_field in select & {'mtime', 'date'}:
        for item in items:
            # date fields with value 0 are returned as ND
            item[date_field] = "ND" if item[date_field] == 0 \
                                    else datetime.fromtimestamp(float(item[date_field]))

    return {'totalItems': totalItems, 'items': items}
